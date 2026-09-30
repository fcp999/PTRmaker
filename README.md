# PTRmaker

PTRmaker is a learning DNS forwarder that forwards DNS queries to an upstream resolver, observes returned DNS data, and builds useful synthetic PTR mappings from the names clients actually queried.

This is useful in environments where reverse DNS otherwise collapses many cloud-hosted services into generic provider names such as AWS hostnames.

## Features

- UDP and TCP DNS forwarding
- Configurable upstream DNS server
- Learns A, AAAA, CNAME, NS, SOA, and PTR relationships
- Follows CNAME chains
- Associates the original queried hostname with returned IP addresses
- Learns authority names and their IP addresses when available
- Synthesizes PTR responses from learned forward lookups
- Stores observations in SQLite
- Keeps first-seen, last-seen, TTL, expiry, source, and hit counts
- Retries truncated UDP responses over TCP
- Retains historical hostname/IP observations after expiry while excluding them from active synthetic PTR answers

## Requirements

- Python 3.9+
- `dnslib`

```bash
python3 -m pip install -r requirements.txt
```

## Run on a test port

```bash
python3 ptrmaker.py --listen 0.0.0.0 --port 5353 --upstream 192.168.0.2 --debug
```

Test it:

```bash
dig @127.0.0.1 -p 5353 www.example.com A
dig @127.0.0.1 -p 5353 -x 93.184.216.34
```

## Run on DNS port 53

```bash
sudo python3 ptrmaker.py --listen 0.0.0.0 --port 53 --upstream 192.168.0.2
```

## Useful SQLite queries

Recent learned names:

```bash
sqlite3 learndns.db '
SELECT ip, name, source, hits,
       datetime(last_seen,"unixepoch","localtime")
FROM names
ORDER BY last_seen DESC;
'
```

Learned authorities:

```bash
sqlite3 learndns.db '
SELECT zone, nameserver, hits,
       datetime(last_seen,"unixepoch","localtime")
FROM authorities
ORDER BY last_seen DESC;
'
```

## How synthetic PTR selection works

PTRmaker prefers learned names in this order:

1. Original queried hostname
2. CNAME alias
3. Returned answer owner name
4. Upstream PTR name
5. Authority name

Synthetic PTR answers are deliberately not marked authoritative. They represent observed DNS relationships, not ownership of the public reverse-DNS zone.

## License

No license has been selected yet.
