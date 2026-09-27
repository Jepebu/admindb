# AdminDB (Administrative Database)

A secure, high-throughput client-server application designed for internal networks. It features a built-in Certificate Authority (CA) for device registration, strict Mutual TLS (mTLS) enforcement for data access, and an asynchronous Redis-backed message queue to handle high volumes of concurrent read/write requests.

## Architecture Overview

The system is split into two primary network interfaces and a background worker:

1. **HTTP Registration API (Port 8080):** Acts as an internal CA. It accepts Certificate Signing Requests (CSRs), verifies the client's identity against local DNS records (or requires localhost for user accounts), and issues a signed certificate.

2. **HTTPS Secure API (Port 8443):** Requires a valid client certificate (mTLS) to connect. It accepts `GET`, `PUT`, `DELETE`, and `/search` operations, placing them onto a Redis task queue. It also handles certificate revocation (`/unregister`).

3. **Background Worker:** Dequeues tasks from Redis, executes them against the database, and publishes the results back to transient response queues for the web threads to consume.

## Prerequisites

* **Python 3.12+** (Required for updated `datetime` timezone handling)
* **Redis Server** running locally on the default port (`localhost:6379`)

## Installation

### With Package Managers

You can download pre-packaged installers here:  
- [Debian Server](https://jepebu.com/downloads/admindb-server_1.0.0_all.deb) (SHA `b300633f7c8694f938f399e5aa3a6299d907f79d76b52e0a7de0a4a4b07cac30`)
- [Debian Client](https://jepebu.com/downloads/admindb-client_1.0.0_all.deb) (SHA `7198d39cca5fff3352e7328113e7c18ff9f9e049093bb26d73f5134c3cb189d5`)
- [Fedora Server](https://jepebu.com/downloads/admindb-server-1.0.0-1.noarch.rpm) (SHA `8a36a06e2bd34355273d85c9bed555044a7ffe86387517799730b56b07c7986c`)
- [Fedora Client](https://jepebu.com/downloads/admindb-client-1.0.0-1.noarch.rpm) (SHA `64191a3ee282bcc966c09eccbf730e71b4ff28a115ab1eaffdc0f24f414d1c09`)


### From Source
1. Clone or copy the project files (`admindb-server.py` and `dbcli`) into your environment.
2. Install the required Python packages:

```bash
pip install Flask redis cryptography requests dnspython werkzeug gunicorn
```

## Running the Server
*Note: Server certificates are securely stored in `/etc/admindb-server/` when run as root, or `./certs/` in your current directory when run locally as a normal user.*

### Option A: Package Manager Install

When installing with a package manager such as `apt`, `dpkg`, `dnf,` or `yum`, the package installs and enables the systemd services for AdminDB.  
This form of AdminDB runs using `gunicorn`.  

```
systemctl status admindb-http admindb-https admindb-worker
```



### Option B: Local Development (Quickstart)

For quick testing and development, you can use the built-in process manager. This will automatically initialize the PKI and spawn the HTTP server, HTTPS server, and Redis worker on different cores.

```bash
# Run with standard DNS verification
python admindb-server.py dev

# Run with DNS verification disabled (accepts any CSR)
python admindb-server.py dev --debug-skip-dns
```

### Option C: Production (Gunicorn)

For production deployments or high-volume environments, you should use `gunicorn` to manage multiple web workers. 

**1. Initialize the PKI infrastructure:**
Generates the CA and server certificates.

```bash
sudo python admindb-server.py init-pki
```

**2. Start the Background Worker:**
(We recommend running this via a `systemd` service or Docker container in production).

```bash
sudo python admindb-server.py worker
```

**3. Start the HTTP CA Server (Port 8080):**

```bash
# Optional: Set this environment variable if you need to bypass DNS checks
# export DEBUG_SKIP_DNS=true 

sudo gunicorn -w 4 -b 0.0.0.0:8080 server:http_app
```

**4. Start the Secure HTTPS mTLS Server (Port 8443):**
*(Note: adjust paths to `./certs/...` if not running as root)*

```bash
sudo gunicorn -w 4 -b 0.0.0.0:8443 \
    --certfile /etc/admindb-server/server.crt \
    --keyfile /etc/admindb-server/server.key \
    --ca-certs /etc/admindb-server/ca.crt \
    --cert-reqs 2 \
    server:https_app
```

## Client Configuration

By default, the client points to `localhost` on ports `8080` and `8443`. You can override these defaults permanently by creating a configuration file.

The client checks for configuration in this order:
1. `/etc/admindb-client/config` (Global System Config)
2. `~/.admindb/config` (User Config - overrides Global)

**Example Configuration Format:**
```ini
[Server]
http_server = http://myserver.internal:8080
https_server = https://myserver.internal:8443
```

## Client Usage

The `dbcli` script provides a command-line interface to interact with the server. It stores its certificates in `~/.admindb/` (or `/etc/admindb-client/` if run as root), which can be overridden via the `--cert-dir` flag.

### 1. Registering an Identity

Generate a private key, send a CSR to the HTTP server, and save the returned certificates locally. 

```bash
# Register a computer (Validates IP against reverse DNS hostname)
dbcli register --type computer --cn my-device.local

# Register a user (Requires command to be executed from localhost on the server)
dbcli register --type user --cn admin_john
```

### 2. Storing Data (PUT)

Requires a valid `client.crt` and `client.key` generated from the `register` command.

```bash
dbcli put my_test_key "This is my secret data"
```

### 3. Retrieving Data (GET)

```bash
dbcli get my_test_key
```

### 4. Searching and Deleting

```bash
# Fetch values for all keys ending in "_key"
dbcli search '*_key'

# Delete a specific key
dbcli delete my_test_key
```

### 5. Unregistering (Revocation)

Revokes the current certificate on the server by adding it to a Redis blocklist, then deletes the local keypair and certificate files.

```bash
dbcli unregister
```

## Troubleshooting

* **"No connection adapters were found"**: Make sure you are formatting custom server URLs properly. Ensure it starts with `http://` or `https://`.
* **"Identity verification failed"**: The DNS lookup failed for your IP address. Ensure your network has correct PTR records, or use `--debug-skip-dns` on the server to bypass this check during testing.
* **"Query timeout, queue is too busy"**: Ensure your `redis-server` is running and that you have started the background worker process (`python admindb-server.py worker`).
