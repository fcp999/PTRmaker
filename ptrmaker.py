#!/usr/bin/env python3

# ptrmaker.py
#
# Learning DNS forwarder.
#
# Features:
#   - Listens on UDP and TCP port 53
#   - Forwards queries to an upstream DNS server
#   - Learns A, AAAA, CNAME, NS, SOA and PTR relationships
#   - Associates the original queried hostname with returned IP addresses
#   - Walks CNAME chains so AWS/CDN canonical names don't destroy useful names
#   - Creates synthetic PTR answers from learned forward lookups
#   - Stores observations in SQLite
#   - Keeps first_seen / last_seen / TTL / expiry / hit count
#   - Supports upstream TCP retry when a UDP response is truncated
#
# Install:
#
#   python3 -m pip install dnslib
#
# Run on a test port first:
#
#   sudo python3 ptrmaker.py \
#       --listen 0.0.0.0 \
#       --port 5353 \
#       --upstream 192.168.0.2
#
# Test:
#
#   dig @127.0.0.1 -p 5353 www.example.com A
#   dig @127.0.0.1 -p 5353 -x 93.184.216.34
#
# Then run on real DNS port:
#
#   sudo python3 ptrmaker.py \
#       --listen 0.0.0.0 \
#       --port 53 \
#       --upstream 192.168.0.2
#
# WARNING:
#   Synthetic PTRs are intentionally NOT authoritative Internet DNS.
#   They represent names this resolver has observed resolving to an IP.
#
# SQLite database defaults to:
#
#   ./learndns.db
#
# Useful queries:
#
#   sqlite3 learndns.db \
#       'select ip,name,source,hits,datetime(last_seen,"unixepoch","localtime") from names order by last_seen desc;'
#
#   sqlite3 learndns.db \
#       'select zone,nameserver,datetime(last_seen,"unixepoch","localtime") from authorities order by last_seen desc;'


import argparse
import ipaddress
import logging
import socket
import socketserver
import sqlite3
import threading
import time

from dnslib import (
    DNSRecord,
    DNSHeader,
    DNSQuestion,
    RR,
    QTYPE,
    RCODE,
    A,
    AAAA,
    CNAME,
    PTR,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DEFAULT_DB = "learndns.db"
DEFAULT_UPSTREAM_PORT = 53
DEFAULT_PTR_TTL = 60

# Don't keep learned records forever merely because Amazon decided that
# today's load balancer should have seventeen names before lunch.
LEARN_MIN_TTL = 300
LEARN_MAX_TTL = 86400

SOCKET_TIMEOUT = 5.0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_name(name):
    """
    dnslib generally represents DNS names with a trailing dot.
    Internally we store lower-case names WITHOUT a trailing dot.
    """
    return str(name).rstrip(".").lower()


def clamp_learn_ttl(ttl):
    ttl = int(ttl)

    if ttl < LEARN_MIN_TTL:
        return LEARN_MIN_TTL

    if ttl > LEARN_MAX_TTL:
        return LEARN_MAX_TTL

    return ttl


def reverse_name_to_ip(name):
    """
    Convert:
        4.3.2.1.in-addr.arpa
    into:
        1.2.3.4

    Also handles IPv6 ip6.arpa names.
    """

    name = normalize_name(name)

    if name.endswith(".in-addr.arpa"):
        body = name[:-len(".in-addr.arpa")]
        parts = body.split(".")

        if len(parts) != 4:
            return None

        try:
            return str(ipaddress.IPv4Address(".".join(reversed(parts))))
        except ValueError:
            return None

    if name.endswith(".ip6.arpa"):
        body = name[:-len(".ip6.arpa")]
        nibbles = body.split(".")

        if len(nibbles) != 32:
            return None

        hex_string = "".join(reversed(nibbles))

        try:
            return str(ipaddress.IPv6Address(int(hex_string, 16)))
        except ValueError:
            return None

    return None


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

class LearningDatabase:

    def __init__(self, filename):
        self.filename = filename
        self.lock = threading.RLock()

        self.db = sqlite3.connect(
            filename,
            check_same_thread=False
        )

        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=NORMAL")

        self.create_schema()

    def create_schema(self):

        with self.lock:
            self.db.executescript(
                """
                CREATE TABLE IF NOT EXISTS names (
                    ip          TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    source      TEXT NOT NULL,
                    first_seen  INTEGER NOT NULL,
                    last_seen   INTEGER NOT NULL,
                    expires     INTEGER NOT NULL,
                    dns_ttl     INTEGER NOT NULL,
                    hits        INTEGER NOT NULL DEFAULT 1,

                    PRIMARY KEY (ip, name, source)
                );

                CREATE INDEX IF NOT EXISTS idx_names_ip
                    ON names(ip);

                CREATE INDEX IF NOT EXISTS idx_names_name
                    ON names(name);

                CREATE INDEX IF NOT EXISTS idx_names_expires
                    ON names(expires);


                CREATE TABLE IF NOT EXISTS cnames (
                    alias       TEXT NOT NULL,
                    target      TEXT NOT NULL,
                    first_seen  INTEGER NOT NULL,
                    last_seen   INTEGER NOT NULL,
                    expires     INTEGER NOT NULL,
                    dns_ttl     INTEGER NOT NULL,
                    hits        INTEGER NOT NULL DEFAULT 1,

                    PRIMARY KEY(alias, target)
                );

                CREATE INDEX IF NOT EXISTS idx_cnames_alias
                    ON cnames(alias);


                CREATE TABLE IF NOT EXISTS authorities (
                    zone        TEXT NOT NULL,
                    nameserver  TEXT NOT NULL,
                    first_seen  INTEGER NOT NULL,
                    last_seen   INTEGER NOT NULL,
                    expires     INTEGER NOT NULL,
                    dns_ttl     INTEGER NOT NULL,
                    hits        INTEGER NOT NULL DEFAULT 1,

                    PRIMARY KEY(zone, nameserver)
                );


                CREATE TABLE IF NOT EXISTS soa (
                    zone        TEXT NOT NULL,
                    primary_ns  TEXT NOT NULL,
                    first_seen  INTEGER NOT NULL,
                    last_seen   INTEGER NOT NULL,
                    expires     INTEGER NOT NULL,
                    dns_ttl     INTEGER NOT NULL,
                    hits        INTEGER NOT NULL DEFAULT 1,

                    PRIMARY KEY(zone, primary_ns)
                );
                """
            )

            self.db.commit()

    def learn_name(self, ip, name, source, ttl):

        ip = str(ip)
        name = normalize_name(name)

        if not name:
            return

        now = int(time.time())
        learned_ttl = clamp_learn_ttl(ttl)
        expires = now + learned_ttl

        with self.lock:
            self.db.execute(
                """
                INSERT INTO names (
                    ip,
                    name,
                    source,
                    first_seen,
                    last_seen,
                    expires,
                    dns_ttl,
                    hits
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 1)

                ON CONFLICT(ip, name, source)
                DO UPDATE SET
                    last_seen = excluded.last_seen,
                    expires   = excluded.expires,
                    dns_ttl   = excluded.dns_ttl,
                    hits      = hits + 1
                """,
                (
                    ip,
                    name,
                    source,
                    now,
                    now,
                    expires,
                    int(ttl),
                )
            )

            self.db.commit()

    def learn_cname(self, alias, target, ttl):

        alias = normalize_name(alias)
        target = normalize_name(target)

        now = int(time.time())
        expires = now + clamp_learn_ttl(ttl)

        with self.lock:
            self.db.execute(
                """
                INSERT INTO cnames (
                    alias,
                    target,
                    first_seen,
                    last_seen,
                    expires,
                    dns_ttl,
                    hits
                )
                VALUES (?, ?, ?, ?, ?, ?, 1)

                ON CONFLICT(alias, target)
                DO UPDATE SET
                    last_seen = excluded.last_seen,
                    expires   = excluded.expires,
                    dns_ttl   = excluded.dns_ttl,
                    hits      = hits + 1
                """,
                (
                    alias,
                    target,
                    now,
                    now,
                    expires,
                    int(ttl),
                )
            )

            self.db.commit()

    def learn_authority(self, zone, nameserver, ttl):

        zone = normalize_name(zone)
        nameserver = normalize_name(nameserver)

        now = int(time.time())
        expires = now + clamp_learn_ttl(ttl)

        with self.lock:
            self.db.execute(
                """
                INSERT INTO authorities (
                    zone,
                    nameserver,
                    first_seen,
                    last_seen,
                    expires,
                    dns_ttl,
                    hits
                )
                VALUES (?, ?, ?, ?, ?, ?, 1)

                ON CONFLICT(zone, nameserver)
                DO UPDATE SET
                    last_seen = excluded.last_seen,
                    expires   = excluded.expires,
                    dns_ttl   = excluded.dns_ttl,
                    hits      = hits + 1
                """,
                (
                    zone,
                    nameserver,
                    now,
                    now,
                    expires,
                    int(ttl),
                )
            )

            self.db.commit()

    def learn_soa(self, zone, primary_ns, ttl):

        zone = normalize_name(zone)
        primary_ns = normalize_name(primary_ns)

        now = int(time.time())
        expires = now + clamp_learn_ttl(ttl)

        with self.lock:
            self.db.execute(
                """
                INSERT INTO soa (
                    zone,
                    primary_ns,
                    first_seen,
                    last_seen,
                    expires,
                    dns_ttl,
                    hits
                )
                VALUES (?, ?, ?, ?, ?, ?, 1)

                ON CONFLICT(zone, primary_ns)
                DO UPDATE SET
                    last_seen = excluded.last_seen,
                    expires   = excluded.expires,
                    dns_ttl   = excluded.dns_ttl,
                    hits      = hits + 1
                """,
                (
                    zone,
                    primary_ns,
                    now,
                    now,
                    expires,
                    int(ttl),
                )
            )

            self.db.commit()

    def get_best_name(self, ip):

        now = int(time.time())

        # Preference order.
        #
        # queried-name is the valuable bit.
        #
        # If someone asked for:
        #
        #   payroll.company.com
        #
        # and AWS eventually replied with:
        #
        #   internal-blah-123.us-east-1.elb.amazonaws.com
        #
        # we want payroll.company.com for our synthetic PTR.

        priority_sql = """
            CASE source
                WHEN 'query'      THEN 1
                WHEN 'cname'      THEN 2
                WHEN 'answer'     THEN 3
                WHEN 'ptr'        THEN 4
                WHEN 'authority'  THEN 5
                ELSE 99
            END
        """

        with self.lock:
            row = self.db.execute(
                f"""
                SELECT name
                FROM names
                WHERE ip = ?
                  AND expires >= ?
                ORDER BY
                    {priority_sql},
                    last_seen DESC,
                    hits DESC
                LIMIT 1
                """,
                (
                    str(ip),
                    now,
                )
            ).fetchone()

        if not row:
            return None

        return row[0]

    def cleanup(self):

        now = int(time.time())

        with self.lock:
            self.db.execute(
                """
                DELETE FROM cnames
                WHERE expires < ?
                """,
                (now,)
            )

            self.db.execute(
                """
                DELETE FROM authorities
                WHERE expires < ?
                """,
                (now,)
            )

            self.db.execute(
                """
                DELETE FROM soa
                WHERE expires < ?
                """,
                (now,)
            )

            # We intentionally leave expired entries in 'names'.
            #
            # That gives us historical passive DNS data.
            #
            # get_best_name() ignores expired entries when answering PTR
            # queries, but the historical mapping remains available in SQLite.

            self.db.commit()


# ---------------------------------------------------------------------------
# DNS learning
# ---------------------------------------------------------------------------

class DNSLearner:

    def __init__(self, database):
        self.db = database

    def process_response(self, query, response):

        if not query.questions:
            return

        question = query.questions[0]

        queried_name = normalize_name(question.qname)

        cname_map = {}
        address_map = {}

        # address_map:
        #
        #   hostname -> [(ip, ttl), ...]
        #
        # cname_map:
        #
        #   alias -> (target, ttl)

        all_records = (
            list(response.rr)
            + list(response.auth)
            + list(response.ar)
        )

        for rr in all_records:

            owner = normalize_name(rr.rname)
            rrtype = rr.rtype
            ttl = int(rr.ttl)

            if rrtype == QTYPE.A:

                ip = str(rr.rdata)

                address_map.setdefault(owner, []).append(
                    (ip, ttl)
                )

                self.db.learn_name(
                    ip,
                    owner,
                    "answer",
                    ttl
                )

            elif rrtype == QTYPE.AAAA:

                ip = str(rr.rdata)

                address_map.setdefault(owner, []).append(
                    (ip, ttl)
                )

                self.db.learn_name(
                    ip,
                    owner,
                    "answer",
                    ttl
                )

            elif rrtype == QTYPE.CNAME:

                target = normalize_name(rr.rdata.label)

                cname_map[owner] = (
                    target,
                    ttl
                )

                self.db.learn_cname(
                    owner,
                    target,
                    ttl
                )

            elif rrtype == QTYPE.NS:

                nameserver = normalize_name(
                    rr.rdata.label
                )

                self.db.learn_authority(
                    owner,
                    nameserver,
                    ttl
                )

            elif rrtype == QTYPE.SOA:

                primary_ns = normalize_name(
                    rr.rdata.mname
                )

                self.db.learn_soa(
                    owner,
                    primary_ns,
                    ttl
                )

            elif rrtype == QTYPE.PTR:

                ip = reverse_name_to_ip(owner)

                if ip:
                    ptr_name = normalize_name(
                        rr.rdata.label
                    )

                    self.db.learn_name(
                        ip,
                        ptr_name,
                        "ptr",
                        ttl
                    )

        # ---------------------------------------------------------------
        # Learn NS address records from the additional section.
        #
        # Example:
        #
        # example.com NS ns1.example.net
        #
        # ADDITIONAL:
        #
        # ns1.example.net A 1.2.3.4
        #
        # That gives:
        #
        # 1.2.3.4 -> ns1.example.net
        # ---------------------------------------------------------------

        authority_names = set()

        for rr in response.auth:

            if rr.rtype == QTYPE.NS:
                authority_names.add(
                    normalize_name(rr.rdata.label)
                )

        for rr in response.ar:

            owner = normalize_name(rr.rname)

            if owner not in authority_names:
                continue

            if rr.rtype in (QTYPE.A, QTYPE.AAAA):

                self.db.learn_name(
                    str(rr.rdata),
                    owner,
                    "authority",
                    int(rr.ttl)
                )

        # ---------------------------------------------------------------
        # Resolve the CNAME chain from the ORIGINAL QUERY.
        #
        # Example:
        #
        # client asks:
        #
        #   app.company.com
        #
        # DNS says:
        #
        #   app.company.com
        #       CNAME foo.elb.amazonaws.com
        #
        #   foo.elb.amazonaws.com
        #       A 52.1.2.3
        #
        # We learn BOTH:
        #
        #   52.1.2.3 -> app.company.com      source=query
        #   52.1.2.3 -> foo.elb.amazonaws.com source=answer
        # ---------------------------------------------------------------

        current = queried_name
        aliases = [queried_name]

        visited = set()

        while current in cname_map:

            if current in visited:
                break

            visited.add(current)

            target, cname_ttl = cname_map[current]

            aliases.append(target)
            current = target

        # Current should now be the final canonical name.

        if current in address_map:

            for ip, addr_ttl in address_map[current]:

                # Original queried name gets highest preference.

                self.db.learn_name(
                    ip,
                    queried_name,
                    "query",
                    addr_ttl
                )

                # Associate intermediate aliases as well.

                for alias in aliases[1:-1]:

                    self.db.learn_name(
                        ip,
                        alias,
                        "cname",
                        addr_ttl
                    )

                logging.info(
                    "LEARN query=%s ip=%s canonical=%s",
                    queried_name,
                    ip,
                    current,
                )

        # ---------------------------------------------------------------
        # Also account for direct A/AAAA answers where no CNAME exists.
        # ---------------------------------------------------------------

        elif queried_name in address_map:

            for ip, addr_ttl in address_map[queried_name]:

                self.db.learn_name(
                    ip,
                    queried_name,
                    "query",
                    addr_ttl
                )

                logging.info(
                    "LEARN query=%s ip=%s",
                    queried_name,
                    ip,
                )


# ---------------------------------------------------------------------------
# Upstream DNS
# ---------------------------------------------------------------------------

class UpstreamResolver:

    def __init__(self, server, port=53):
        self.server = server
        self.port = port

    def query_udp(self, packet):

        sock = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        sock.settimeout(SOCKET_TIMEOUT)

        try:
            sock.sendto(
                packet,
                (
                    self.server,
                    self.port,
                )
            )

            data, _ = sock.recvfrom(65535)

            return data

        finally:
            sock.close()

    def query_tcp(self, packet):

        sock = socket.create_connection(
            (
                self.server,
                self.port,
            ),
            timeout=SOCKET_TIMEOUT
        )

        try:

            length = len(packet)

            sock.sendall(
                length.to_bytes(
                    2,
                    "big"
                )
                + packet
            )

            header = self.recv_exact(
                sock,
                2
            )

            response_length = int.from_bytes(
                header,
                "big"
            )

            return self.recv_exact(
                sock,
                response_length
            )

        finally:
            sock.close()

    @staticmethod
    def recv_exact(sock, length):

        data = bytearray()

        while len(data) < length:

            chunk = sock.recv(
                length - len(data)
            )

            if not chunk:
                raise ConnectionError(
                    "upstream DNS TCP connection closed"
                )

            data.extend(chunk)

        return bytes(data)

    def resolve(self, packet, force_tcp=False):

        if force_tcp:
            return self.query_tcp(packet)

        response_packet = self.query_udp(packet)

        response = DNSRecord.parse(
            response_packet
        )

        # Retry with TCP if upstream DNS says:
        #
        #   TC = truncated

        if response.header.tc:

            logging.debug(
                "Upstream response truncated; retrying via TCP"
            )

            return self.query_tcp(packet)

        return response_packet


# ---------------------------------------------------------------------------
# DNS application
# ---------------------------------------------------------------------------

class DNSApplication:

    def __init__(
        self,
        database,
        learner,
        upstream,
        ptr_ttl=DEFAULT_PTR_TTL,
    ):
        self.db = database
        self.learner = learner
        self.upstream = upstream
        self.ptr_ttl = ptr_ttl

    def make_error_response(
        self,
        query,
        rcode=RCODE.SERVFAIL
    ):

        reply = query.reply()

        reply.header.rcode = rcode

        return reply.pack()

    def synthetic_ptr(self, query):

        if not query.questions:
            return None

        question = query.questions[0]

        if question.qtype != QTYPE.PTR:
            return None

        ip = reverse_name_to_ip(
            question.qname
        )

        if not ip:
            return None

        learned_name = self.db.get_best_name(
            ip
        )

        if not learned_name:
            return None

        reply = query.reply()

        # We are NOT authoritative for the real reverse-DNS zone.
        #
        # AA stays false.

        reply.add_answer(
            RR(
                rname=question.qname,
                rtype=QTYPE.PTR,
                rclass=1,
                ttl=self.ptr_ttl,
                rdata=PTR(
                    learned_name + "."
                ),
            )
        )

        logging.info(
            "SYNTH-PTR ip=%s name=%s",
            ip,
            learned_name,
        )

        return reply.pack()

    def handle(self, packet, tcp=False):

        try:
            query = DNSRecord.parse(
                packet
            )

        except Exception:

            logging.exception(
                "Unable to parse DNS query"
            )

            return None

        # ---------------------------------------------------------------
        # Answer PTR from our learned DNS observations if possible.
        # ---------------------------------------------------------------

        synthetic = self.synthetic_ptr(
            query
        )

        if synthetic is not None:
            return synthetic

        # ---------------------------------------------------------------
        # Otherwise forward query upstream.
        # ---------------------------------------------------------------

        try:

            response_packet = self.upstream.resolve(
                packet,
                force_tcp=tcp
            )

        except Exception:

            logging.exception(
                "Upstream DNS failure"
            )

            return self.make_error_response(
                query
            )

        try:

            response = DNSRecord.parse(
                response_packet
            )

            self.learner.process_response(
                query,
                response
            )

        except Exception:

            # Never break DNS simply because our learning code failed.
            #
            # DNS forwarding is the primary job.
            # Learning is secondary.

            logging.exception(
                "Error learning from DNS response"
            )

        return response_packet


# ---------------------------------------------------------------------------
# UDP server
# ---------------------------------------------------------------------------

class UDPDNSHandler(socketserver.BaseRequestHandler):

    def handle(self):

        packet, sock = self.request

        response = self.server.app.handle(
            packet,
            tcp=False
        )

        if response:

            sock.sendto(
                response,
                self.client_address
            )


class ThreadingUDPServer(
    socketserver.ThreadingMixIn,
    socketserver.UDPServer
):

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address,
        handler,
        app,
    ):
        self.app = app

        super().__init__(
            address,
            handler
        )


# ---------------------------------------------------------------------------
# TCP server
# ---------------------------------------------------------------------------

class TCPDNSHandler(socketserver.BaseRequestHandler):

    def recv_exact(self, length):

        data = bytearray()

        while len(data) < length:

            chunk = self.request.recv(
                length - len(data)
            )

            if not chunk:
                return None

            data.extend(chunk)

        return bytes(data)

    def handle(self):

        while True:

            header = self.recv_exact(2)

            if not header:
                return

            length = int.from_bytes(
                header,
                "big"
            )

            packet = self.recv_exact(
                length
            )

            if not packet:
                return

            response = self.server.app.handle(
                packet,
                tcp=True
            )

            if response is None:
                return

            self.request.sendall(
                len(response).to_bytes(
                    2,
                    "big"
                )
                + response
            )


class ThreadingTCPServer(
    socketserver.ThreadingMixIn,
    socketserver.TCPServer
):

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        address,
        handler,
        app,
    ):

        self.app = app

        super().__init__(
            address,
            handler
        )


# ---------------------------------------------------------------------------
# Cleanup thread
# ---------------------------------------------------------------------------

def cleanup_thread(database):

    while True:

        time.sleep(300)

        try:
            database.cleanup()

        except Exception:
            logging.exception(
                "Database cleanup failed"
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():

    parser = argparse.ArgumentParser(
        description=(
            "Learning DNS forwarder with synthetic PTR records"
        )
    )

    parser.add_argument(
        "--listen",
        default="0.0.0.0",
        help="address to listen on"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=53,
        help="DNS listening port"
    )

    parser.add_argument(
        "--upstream",
        default="192.168.0.2",
        help="upstream DNS server"
    )

    parser.add_argument(
        "--upstream-port",
        type=int,
        default=53,
        help="upstream DNS port"
    )

    parser.add_argument(
        "--database",
        default=DEFAULT_DB,
        help="SQLite database filename"
    )

    parser.add_argument(
        "--ptr-ttl",
        type=int,
        default=DEFAULT_PTR_TTL,
        help="TTL for synthetic PTR responses"
    )

    parser.add_argument(
        "--debug",
        action="store_true"
    )

    args = parser.parse_args()

    logging.basicConfig(
        level=(
            logging.DEBUG
            if args.debug
            else logging.INFO
        ),
        format=(
            "%(asctime)s "
            "%(levelname)s "
            "%(message)s"
        )
    )

    database = LearningDatabase(
        args.database
    )

    learner = DNSLearner(
        database
    )

    upstream = UpstreamResolver(
        args.upstream,
        args.upstream_port
    )

    app = DNSApplication(
        database,
        learner,
        upstream,
        args.ptr_ttl
    )

    udp_server = ThreadingUDPServer(
        (
            args.listen,
            args.port,
        ),
        UDPDNSHandler,
        app
    )

    tcp_server = ThreadingTCPServer(
        (
            args.listen,
            args.port,
        ),
        TCPDNSHandler,
        app
    )

    threading.Thread(
        target=udp_server.serve_forever,
        daemon=True
    ).start()

    threading.Thread(
        target=cleanup_thread,
        args=(database,),
        daemon=True
    ).start()

    logging.info(
        "Learning DNS listening on %s:%d UDP/TCP",
        args.listen,
        args.port
    )

    logging.info(
        "Forwarding DNS to %s:%d",
        args.upstream,
        args.upstream_port
    )

    logging.info(
        "Database: %s",
        args.database
    )

    try:

        tcp_server.serve_forever()

    except KeyboardInterrupt:

        logging.info(
            "Stopping DNS server"
        )

    finally:

        udp_server.shutdown()
        tcp_server.shutdown()


if __name__ == "__main__":
    main()