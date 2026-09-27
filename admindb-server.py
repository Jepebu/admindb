#!/usr/bin/env python3

import os
import json
import uuid
import socket
import ssl
import ipaddress
import multiprocessing
import urllib.parse
import werkzeug.serving
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, abort
import redis
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID

# Determine the default certificate directory based on the user context
if hasattr(os, 'geteuid') and os.geteuid() == 0:
    CERT_DIR = os.environ.get('ADMINDB_CERT_DIR', '/etc/admindb-server')
else:
    # Default to a local 'certs' directory for non-root development
    CERT_DIR = os.environ.get('ADMINDB_CERT_DIR', os.path.join(os.path.abspath(os.path.dirname(__file__)), 'certs'))

CA_CRT = os.path.join(CERT_DIR, "ca.crt")
CA_KEY = os.path.join(CERT_DIR, "ca.key")
SERVER_CRT = os.path.join(CERT_DIR, "server.crt")
SERVER_KEY = os.path.join(CERT_DIR, "server.key")

def ensure_pki():
    """Generates the internal Certificate Authority and Server Certificate if they don't exist."""
    os.makedirs(CERT_DIR, exist_ok=True)

    if not os.path.exists(CA_CRT):
        print(f"[PKI] Generating new Certificate Authority (CA) in {CERT_DIR}...")
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"AdminDB CA")])
        ca_cert = x509.CertificateBuilder().subject_name(ca_subject).issuer_name(ca_subject).public_key(
            ca_key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=3650)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(ca_key, hashes.SHA256())

        with open(CA_KEY, "wb") as f:
            f.write(ca_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(CA_CRT, "wb") as f:
            f.write(ca_cert.public_bytes(serialization.Encoding.PEM))

    if not os.path.exists(SERVER_CRT):
        print(f"[PKI] Generating new Server Certificate in {CERT_DIR}...")
        with open(CA_KEY, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CRT, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())

        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        server_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"localhost")])

        server_cert = x509.CertificateBuilder().subject_name(server_subject).issuer_name(ca_cert.subject).public_key(
            server_key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.now(timezone.utc)
        ).not_valid_after(
            datetime.now(timezone.utc) + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"localhost"),
                x509.IPAddress(ipaddress.IPv4Address(u"127.0.0.1"))
            ]), critical=False,
        ).sign(ca_key, hashes.SHA256())

        with open(SERVER_KEY, "wb") as f:
            f.write(server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open(SERVER_CRT, "wb") as f:
            f.write(server_cert.public_bytes(serialization.Encoding.PEM))

http_app = Flask("http_app")

# For WSGI compatibility, we read the debug flag from the environment variables
http_app.config['DEBUG_SKIP_DNS'] = os.environ.get('DEBUG_SKIP_DNS', 'False').lower() == 'true'

@http_app.route('/register', methods=['POST'])
def register():
    """Accepts a CSR, verifies client identity against DNS, and issues a certificate."""
    try:
        csr = x509.load_pem_x509_csr(request.data)
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception as e:
        return jsonify({"error": "Invalid CSR format."}), 400

    remote_ip = request.remote_addr
    valid_names = [remote_ip]
    try:
        hostname, aliases, _ = socket.gethostbyaddr(remote_ip)
        valid_names.extend([hostname] + aliases)
    except socket.herror:
        pass

    if remote_ip == "127.0.0.1":
        valid_names.extend(["localhost"])

    if not http_app.config.get('DEBUG_SKIP_DNS', False):
        if cn not in valid_names:
            return jsonify({"error": f"Identity verification failed. CN '{cn}' not mapped to IP {remote_ip} in DNS."}), 403
    else:
        print(f"[DEBUG] Bypassing DNS verification for CN '{cn}' from IP {remote_ip} due to debug flag.")

    with open(CA_KEY, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CRT, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    client_cert = x509.CertificateBuilder().subject_name(csr.subject).issuer_name(ca_cert.subject).public_key(
        csr.public_key()
    ).serial_number(x509.random_serial_number()).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)
    ).sign(ca_key, hashes.SHA256())

    return jsonify({
        "certificate": client_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
        "ca_certificate": ca_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')
    }), 200

def get_client_cert():
    """
    Robustly extracts the client's mTLS certificate regardless of the WSGI server.
    """
    environ = request.environ

    # 1. Gunicorn socket injection
    sock = environ.get('gunicorn.socket')
    if sock:
        try:
            cert_der = sock.getpeercert(binary_form=True)
            if cert_der:
                return x509.load_der_x509_certificate(cert_der)
        except Exception:
            pass

    # 2. Proxy Header (e.g. Nginx $ssl_client_escaped_cert)
    pem_cert = request.headers.get('X-Client-Cert')
    if pem_cert:
        pem_cert = urllib.parse.unquote(pem_cert)
        pem_cert = pem_cert.replace('\t', '')
        try:
            return x509.load_pem_x509_certificate(pem_cert.encode('utf-8'))
        except Exception:
            pass

    # 3. Local Dev Werkzeug Injection
    if 'SSL_CLIENT_CERT' in environ:
        return x509.load_der_x509_certificate(environ['SSL_CLIENT_CERT'])

    return None

class PeerCertWSGIRequestHandler(werkzeug.serving.WSGIRequestHandler):
    """Local Dev WSGI handler to inject the client's mTLS certificate."""
    def make_environ(self):
        environ = super(PeerCertWSGIRequestHandler, self).make_environ()
        x509_binary = self.connection.getpeercert(True)
        if x509_binary:
            environ['SSL_CLIENT_CERT'] = x509_binary
        return environ

https_app = Flask("https_app")
r_client = redis.Redis(host='localhost', port=6379, db=0)

@https_app.before_request
def check_revocation():
    """Middleware to enforce Certificate Revocation checking via Redis."""
    cert = get_client_cert()
    if not cert:
        return jsonify({"error": "mTLS Certificate required"}), 401

    serial = str(cert.serial_number)
    if r_client.sismember("revoked_certs", serial):
        return jsonify({"error": "Certificate has been revoked."}), 403

@https_app.route('/unregister', methods=['POST'])
def unregister():
    """Revokes the current client certificate by adding its serial to the Redis blocklist."""
    cert = get_client_cert()
    serial = str(cert.serial_number)
    r_client.sadd("revoked_certs", serial)
    return jsonify({"message": "Certificate successfully unregistered/revoked."}), 200

@https_app.route('/data/<key>', methods=['GET', 'PUT', 'DELETE'])
def handle_data(key):
    """Enqueues GET, PUT, and DELETE requests to a message queue for high-volume handling."""
    req_id = str(uuid.uuid4())

    if request.method == 'PUT':
        value = request.get_data(as_text=True)
        task = json.dumps({"action": "put", "key": key, "value": value, "req_id": req_id})
        r_client.rpush("task_queue", task)
        return jsonify({"status": "queued", "req_id": req_id}), 202

    elif request.method in ['GET', 'DELETE']:
        action = 'get' if request.method == 'GET' else 'delete'
        task = json.dumps({"action": action, "key": key, "req_id": req_id})
        r_client.rpush("task_queue", task)

        resp_queue = f"response:{req_id}"
        result = r_client.blpop(resp_queue, timeout=5)

        if result:
            _, data = result
            resp_data = json.loads(data)

            if action == 'get':
                if resp_data.get('found'):
                    return jsonify({"key": key, "value": resp_data['value']}), 200
                return jsonify({"error": "Key not found"}), 404
            elif action == 'delete':
                if resp_data.get('deleted'):
                    return jsonify({"message": f"Key '{key}' deleted successfully"}), 200
                return jsonify({"error": "Key not found"}), 404

        return jsonify({"error": "Query timeout, queue is too busy"}), 504

@https_app.route('/search', methods=['GET'])
def handle_search():
    """Enqueues a SEARCH request to the message queue utilizing shell-style matching."""
    pattern = request.args.get('q', '*')
    req_id = str(uuid.uuid4())

    task = json.dumps({"action": "search", "pattern": pattern, "req_id": req_id})
    r_client.rpush("task_queue", task)

    resp_queue = f"response:{req_id}"
    result = r_client.blpop(resp_queue, timeout=5)

    if result:
        _, data = result
        resp_data = json.loads(data)
        return jsonify({"results": resp_data.get('results', {})}), 200

    return jsonify({"error": "Query timeout, queue is too busy"}), 504

def redis_worker_process():
    """Background process that dequeues requests and executes them against the database."""
    print("[Worker] Started background Redis message queue worker...")
    worker_redis = redis.Redis(host='localhost', port=6379, db=0)

    while True:
        try:
            _, msg = worker_redis.blpop("task_queue")
            task = json.loads(msg)

            action = task.get('action')
            req_id = task.get('req_id')
            key = task.get('key')

            if action == 'put':
                worker_redis.set(key, task['value'])
            elif action == 'get':
                val = worker_redis.get(key)
                resp = {"found": val is not None}
                if val:
                    resp['value'] = val.decode('utf-8')

                resp_key = f"response:{req_id}"
                worker_redis.rpush(resp_key, json.dumps(resp))
                worker_redis.expire(resp_key, 10)
            elif action == 'delete':
                # Redis returns the integer number of keys that were removed
                deleted_count = worker_redis.delete(key)
                resp = {"deleted": deleted_count > 0}

                resp_key = f"response:{req_id}"
                worker_redis.rpush(resp_key, json.dumps(resp))
                worker_redis.expire(resp_key, 10)
            elif action == 'search':
                pattern = task.get('pattern', '*')
                # Redis natively supports glob-style pattern matching with the keys() command
                matched_keys = worker_redis.keys(pattern)

                results = {}
                if matched_keys:
                    # Fetch all values for the matched keys in a single operation
                    values = worker_redis.mget(matched_keys)
                    for k, v in zip(matched_keys, values):
                        results[k.decode('utf-8')] = v.decode('utf-8') if v is not None else None

                resp = {"results": results}

                resp_key = f"response:{req_id}"
                worker_redis.rpush(resp_key, json.dumps(resp))
                worker_redis.expire(resp_key, 10)

        except Exception as e:
            print(f"[Worker] Error processing task: {e}")

def run_dev_servers():
    """Fallback runner for local development and testing."""
    def _run_http():
        print("[HTTP] Listening for CSRs on port 8080...")
        http_app.run(host='0.0.0.0', port=8080, debug=False)

    def _run_https():
        print("[HTTPS] Listening for mTLS Secure API on port 8443...")
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=SERVER_CRT, keyfile=SERVER_KEY)
        context.load_verify_locations(cafile=CA_CRT)
        context.verify_mode = ssl.CERT_REQUIRED

        werkzeug.serving.run_simple(
            '0.0.0.0', 8443, https_app,
            ssl_context=context,
            request_handler=PeerCertWSGIRequestHandler
        )

    p1 = multiprocessing.Process(target=_run_http)
    p2 = multiprocessing.Process(target=_run_https)
    p3 = multiprocessing.Process(target=redis_worker_process)

    p1.start()
    p2.start()
    p3.start()
    p1.join()
    p2.join()
    p3.join()

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description="mTLS Server Application")
    parser.add_argument('mode', choices=['dev', 'worker', 'init-pki'],
                        help="Run mode. Use Gunicorn for production instead of 'dev'.")
    parser.add_argument('--debug-skip-dns', action='store_true', help="Bypass DNS verification for testing")
    args = parser.parse_args()

    if args.debug_skip_dns:
        os.environ['DEBUG_SKIP_DNS'] = 'true'

    if args.mode == 'init-pki':
        ensure_pki()
        print("PKI Initialized successfully.")
    elif args.mode == 'worker':
        redis_worker_process()
    elif args.mode == 'dev':
        ensure_pki()
        run_dev_servers()
