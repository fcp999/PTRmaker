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
--ptr-ttl     synthetic PTR TTL       default: 60
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
