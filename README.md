# PTRmaker

PTRmaker is a learning DNS forwarder written in Go. It forwards DNS queries to an upstream resolver, observes the replies, and builds useful synthetic PTR mappings from the names clients actually queried.

This is especially useful when reverse DNS otherwise collapses cloud-hosted services into generic provider names such as AWS hostnames.

## Features

- UDP and TCP DNS listeners
- Preserves TCP client queries as TCP upstream
- Retries truncated UDP responses over TCP
- Configurable upstream DNS server
- Learns A, AAAA, CNAME, NS, SOA, and PTR relationships
- Walks CNAME chains and associates the original queried hostname with returned IPs
- Learns authority names and glue IPs
- Resolves authority A/AAAA addresses when glue is missing
- Synthesizes PTR responses from learned forward lookups
- Stores observations in SQLite
- Retains first-seen, last-seen, TTL, expiry, source, and hit count
- Retains historical hostname/IP observations after expiry while excluding them from active synthetic PTR answers
- Ignores RFC 8145-style `_ta-*` trust-anchor signaling for learned hostname mappings
- Single compiled binary; no Python runtime or virtual environment required
- Built-in HTTP status dashboard
- JSON lookup API for current and historical mappings
- Prometheus-compatible metrics endpoint
- Health endpoint for monitoring
- Optional JSON-line logging
- systemd service and installer

## Requirements

- Go 1.24 or newer

Dependencies are managed by Go modules.

## Build

```bash
git clone https://github.com/fcp999/PTRmaker.git
cd PTRmaker
go build -o ptrmaker .
```

## Run on a test port

```bash
./ptrmaker   --listen 0.0.0.0:5353   --upstream 192.168.0.2:53   --database ptrmaker.db
```

Test forward DNS:

```bash
dig @127.0.0.1 -p 5353 www.example.com A
```

After an address has been learned, test the synthetic PTR:

```bash
dig @127.0.0.1 -p 5353 -x 93.184.216.34
```

Test TCP explicitly:

```bash
dig +tcp @127.0.0.1 -p 5353 www.example.com A
```

## Run on port 53

```bash
sudo ./ptrmaker   --listen 0.0.0.0:53   --upstream 192.168.0.2:53   --database /var/lib/ptrmaker/ptrmaker.db
```

## Options

```text
--listen      DNS listen address      default: 0.0.0.0:53
--upstream    upstream DNS server     default: 192.168.0.2:53
--database    SQLite database path    default: ptrmaker.db
--ptr-ttl       synthetic PTR TTL                default: 60
--http-listen   HTTP dashboard/API/metrics bind   default: 127.0.0.1:8080
--json-logs     emit structured JSON logs         default: false
```

## HTTP dashboard and API

By default PTRmaker exposes the local status service at:

```text
http://127.0.0.1:8080/
```

Bind it to the LAN if desired:

```bash
./ptrmaker --http-listen 0.0.0.0:8080 --upstream 192.168.0.2:53
```

Useful endpoints:

```text
/                              status dashboard
/healthz                       health check
/metrics                       Prometheus metrics
/api/v1/lookup/203.0.113.10    all learned names for an IP
/api/v1/recent?limit=100       recent learned mappings
/api/v1/authorities?limit=100  recent authority records
```

Example:

```bash
curl http://127.0.0.1:8080/api/v1/lookup/203.0.113.10
curl http://127.0.0.1:8080/metrics
```

The HTTP service defaults to loopback intentionally. If you bind it to `0.0.0.0`, protect it with your firewall or reverse proxy because the API exposes observed DNS mappings.

## JSON logging

```bash
./ptrmaker --json-logs --upstream 192.168.0.2:53
```

Each log entry is emitted as one JSON object, which makes PTRmaker less offensive to log collectors.

## systemd installation

On a Linux system with Go installed:

```bash
git clone https://github.com/fcp999/PTRmaker.git
cd PTRmaker
sudo bash install.sh
```

The installer:

- builds and installs `/usr/local/bin/ptrmaker`
- creates an unprivileged `ptrmaker` service account
- stores the database under `/var/lib/ptrmaker`
- installs `/etc/ptrmaker/ptrmaker.env`
- installs and enables the hardened systemd service
- grants only `CAP_NET_BIND_SERVICE` so PTRmaker can bind port 53 without running as root

Edit the runtime arguments:

```bash
sudo vi /etc/ptrmaker/ptrmaker.env
sudo systemctl restart ptrmaker
```

Operational commands:

```bash
systemctl status ptrmaker
journalctl -u ptrmaker -f
curl http://127.0.0.1:8080/healthz
```

## PTR preference

PTRmaker chooses the best currently valid name for an IP in this order:

1. Original queried hostname
2. CNAME alias
3. Returned answer owner name
4. Upstream PTR name
5. Authority name

Synthetic PTR answers are deliberately not authoritative. They represent observed DNS relationships, not ownership of the public reverse-DNS zone.

## SQLite examples

Recent learned names:

```bash
sqlite3 ptrmaker.db '
SELECT ip, name, source, hits,
       datetime(first_seen,"unixepoch","localtime") AS first_seen,
       datetime(last_seen,"unixepoch","localtime") AS last_seen,
       dns_ttl
FROM names
ORDER BY last_seen DESC;
'
```

Learned authorities:

```bash
sqlite3 ptrmaker.db '
SELECT zone, nameserver, hits,
       datetime(last_seen,"unixepoch","localtime") AS last_seen
FROM authorities
ORDER BY last_seen DESC;
'
```

## License

MIT License. See [LICENSE](LICENSE).
