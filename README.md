# AdminDB (Administrative Database)

A secure, high-throughput client-server application designed for internal networks. It features a built-in Certificate Authority (CA) for device registration, strict Mutual TLS (mTLS) enforcement for data access, and an asynchronous Redis-backed message queue to handle high volumes of concurrent read/write requests.

## Architecture Overview

The system is split into two primary network interfaces and a background worker:
1. **HTTP Registration API (Port 8080):** Acts as an internal CA. It accepts Certificate Signing Requests (CSRs), verifies the client's identity against local DNS records, and issues a signed certificate.
2. **HTTPS Secure API (Port 8443):** Requires a valid client certificate (mTLS) to connect. It accepts `GET` and `PUT` operations, placing them onto a Redis task queue. It also handles certificate revocation (`/unregister`).
3. **Background Worker:** Dequeues tasks from Redis, executes them against the database, and publishes the results back to transient response queues for the web threads to consume.

## Prerequisites

- **Python 3.12+** (Required for updated `datetime` timezone handling)
- **Redis Server** running locally on the default port (`localhost:6379`)

## Installation

### With Package Managers
You can download pre-packages installers here:  
- (Debian Server)[https://jepebu.com/downloads/admindb_1.0.0_all.deb]
- (Debian Client)[https://jepebu.com/downloads/admindb-client_1.0.0_all.deb]
- (Fedora Server)[https://jepebu.com/downloads/admindb-1.0.0-1.noarch.rpm]
- (Fedora Client)[https://jepebu.com/downloads/admindb-client-1.0.0-1.noarch.rpm]



### Building From Source
1. Clone or copy the project files (`server.py` and `client.py`) into your environment.
2. Install the required Python packages:

```bash
pip install Flask redis cryptography requests dnspython werkzeug gunicorn
```

## Running the Server

### Option A: Local Development (Quickstart)
For quick testing and development, you can use the built-in process manager. This will automatically initialize the PKI and spawn the HTTP server, HTTPS server, and Redis worker on different cores.

```bash
# Run with standard DNS verification
python server.py dev

# Run with DNS verification disabled (accepts any CSR)
python server.py dev --debug-skip-dns
```

### Option B: Production (Gunicorn)
For production deployments or high-volume environments, you should use `gunicorn` to manage multiple web workers.

**1. Initialize the PKI infrastructure:**
Generates the CA and server certificates (`ca.crt`, `ca.key`, `server.crt`, `server.key`).
```bash
python server.py init-pki
```

**2. Start the Background Worker:**
(We recommend running this via a `systemd` service or Docker container in production).
```bash
python server.py worker
```

**3. Start the HTTP CA Server (Port 8080):**
```bash
# Optional: Set this environment variable if you need to bypass DNS checks
# export DEBUG_SKIP_DNS=true 

gunicorn -w 4 -b 0.0.0.0:8080 server:http_app
```

**4. Start the Secure HTTPS mTLS Server (Port 8443):**
```bash
gunicorn -w 4 -b 0.0.0.0:8443 \
    --certfile server.crt \
    --keyfile server.key \
    --ca-certs ca.crt \
    --cert-reqs 2 \
    server:https_app
```

## Client Usage

The `client.py` script provides a command-line interface to interact with the server.

### 1. Registering a Device
Generate a private key, send a CSR to the HTTP server, and save the returned certificates locally. By default, the Common Name (CN) is `localhost`.
```bash
# Default registration
python client.py register

# Registering a specific device hostname (must match reverse DNS unless bypassed)
python client.py register --cn my-device.local
```

### 2. Storing Data (PUT)
Requires a valid `client.crt` and `client.key` generated from the `register` command.
```bash
python client.py put my_test_key "This is my secret data"
```

### 3. Retrieving Data (GET)
```bash
python client.py get my_test_key
```

### 4. Unregistering (Revocation)
Revokes the current certificate on the server by adding it to a Redis blocklist, then deletes the local keypair and certificate files.
```bash
python client.py unregister
```

## Troubleshooting

- **"No connection adapters were found"**: Make sure you are formatting custom server URLs properly if you use the `--http-server` flag. Ensure it starts with `http://` or `https://`.
- **"Identity verification failed"**: The DNS lookup failed for your IP address. Ensure your network has correct PTR records, or use `--debug-skip-dns` on the server to bypass this check during testing.
- **"Query timeout, queue is too busy"**: Ensure your `redis-server` is running and that you have started the background worker process (`python server.py worker`).
