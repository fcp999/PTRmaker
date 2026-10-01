package main

import (
	"database/sql"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
	_ "modernc.org/sqlite"
)

const (
	defaultDB       = "ptrmaker.db"
	defaultPTRTTL   = 60
	learnMinTTL     = 300
	learnMaxTTL     = 86400
	upstreamTimeout = 5 * time.Second
)

type Store struct {
	db *sql.DB
}

func NewStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if err := s.initSchema(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) initSchema() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS names (
  ip TEXT NOT NULL,
  name TEXT NOT NULL,
  source TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  expires INTEGER NOT NULL,
  dns_ttl INTEGER NOT NULL,
  hits INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (ip, name, source)
);
CREATE INDEX IF NOT EXISTS idx_names_ip ON names(ip);
CREATE INDEX IF NOT EXISTS idx_names_name ON names(name);
CREATE INDEX IF NOT EXISTS idx_names_expires ON names(expires);

CREATE TABLE IF NOT EXISTS cnames (
  alias TEXT NOT NULL,
  target TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  expires INTEGER NOT NULL,
  dns_ttl INTEGER NOT NULL,
  hits INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(alias, target)
);

CREATE TABLE IF NOT EXISTS authorities (
  zone TEXT NOT NULL,
  nameserver TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  expires INTEGER NOT NULL,
  dns_ttl INTEGER NOT NULL,
  hits INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(zone, nameserver)
);

CREATE TABLE IF NOT EXISTS soa (
  zone TEXT NOT NULL,
  primary_ns TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  expires INTEGER NOT NULL,
  dns_ttl INTEGER NOT NULL,
  hits INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY(zone, primary_ns)
);
`)
	return err
}

func normalizeName(s string) string {
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

func learnTTL(ttl uint32) int64 {
	v := int64(ttl)
	if v < learnMinTTL {
		return learnMinTTL
	}
	if v > learnMaxTTL {
		return learnMaxTTL
	}
	return v
}

func (s *Store) LearnName(ip, name, source string, ttl uint32) error {
	name = normalizeName(name)
	if name == "" || strings.HasPrefix(name, "_ta-") {
		return nil
	}
	now := time.Now().Unix()
	expires := now + learnTTL(ttl)
	_, err := s.db.Exec(`
INSERT INTO names(ip,name,source,first_seen,last_seen,expires,dns_ttl,hits)
VALUES(?,?,?,?,?,?,?,1)
ON CONFLICT(ip,name,source) DO UPDATE SET
 last_seen=excluded.last_seen,
 expires=excluded.expires,
 dns_ttl=excluded.dns_ttl,
 hits=hits+1`, ip, name, source, now, now, expires, ttl)
	return err
}

func (s *Store) LearnCNAME(alias, target string, ttl uint32) error {
	alias, target = normalizeName(alias), normalizeName(target)
	now := time.Now().Unix()
	_, err := s.db.Exec(`
INSERT INTO cnames(alias,target,first_seen,last_seen,expires,dns_ttl,hits)
VALUES(?,?,?,?,?,?,1)
ON CONFLICT(alias,target) DO UPDATE SET
 last_seen=excluded.last_seen,
 expires=excluded.expires,
 dns_ttl=excluded.dns_ttl,
 hits=hits+1`, alias, target, now, now, now+learnTTL(ttl), ttl)
	return err
}

func (s *Store) LearnAuthority(zone, ns string, ttl uint32) error {
	zone, ns = normalizeName(zone), normalizeName(ns)
	now := time.Now().Unix()
	_, err := s.db.Exec(`
INSERT INTO authorities(zone,nameserver,first_seen,last_seen,expires,dns_ttl,hits)
VALUES(?,?,?,?,?,?,1)
ON CONFLICT(zone,nameserver) DO UPDATE SET
 last_seen=excluded.last_seen,
 expires=excluded.expires,
 dns_ttl=excluded.dns_ttl,
 hits=hits+1`, zone, ns, now, now, now+learnTTL(ttl), ttl)
	return err
}

func (s *Store) LearnSOA(zone, ns string, ttl uint32) error {
	zone, ns = normalizeName(zone), normalizeName(ns)
	now := time.Now().Unix()
	_, err := s.db.Exec(`
INSERT INTO soa(zone,primary_ns,first_seen,last_seen,expires,dns_ttl,hits)
VALUES(?,?,?,?,?,?,1)
ON CONFLICT(zone,primary_ns) DO UPDATE SET
 last_seen=excluded.last_seen,
 expires=excluded.expires,
 dns_ttl=excluded.dns_ttl,
 hits=hits+1`, zone, ns, now, now, now+learnTTL(ttl), ttl)
	return err
}

func (s *Store) BestName(ip string) (string, bool, error) {
	row := s.db.QueryRow(`
SELECT name FROM names
WHERE ip=? AND expires>=?
ORDER BY CASE source
 WHEN 'query' THEN 1
 WHEN 'cname' THEN 2
 WHEN 'answer' THEN 3
 WHEN 'ptr' THEN 4
 WHEN 'authority' THEN 5
 ELSE 99 END,
 last_seen DESC, hits DESC
LIMIT 1`, ip, time.Now().Unix())
	var name string
	if err := row.Scan(&name); err != nil {
		if err == sql.ErrNoRows {
			return "", false, nil
		}
		return "", false, err
	}
	return name, true, nil
}

func (s *Store) Cleanup() error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`DELETE FROM cnames WHERE expires<?;
DELETE FROM authorities WHERE expires<?;
DELETE FROM soa WHERE expires<?;`, now, now, now)
	return err
}

type cnameLink struct {
	target string
	ttl    uint32
}

type ipRecord struct {
	ip  string
	ttl uint32
}

type App struct {
	store     *Store
	upstream  string
	ptrTTL    uint32
	metrics   *Metrics
	udpClient *dns.Client
	tcpClient *dns.Client
}

func NewApp(store *Store, upstream string, ptrTTL uint32, metrics *Metrics) *App {
	return &App{
		store:     store,
		upstream:  upstream,
		ptrTTL:    ptrTTL,
		metrics:   metrics,
		udpClient: &dns.Client{Net: "udp", Timeout: upstreamTimeout},
		tcpClient: &dns.Client{Net: "tcp", Timeout: upstreamTimeout},
	}
}

func (a *App) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		dns.HandleFailed(w, req)
		return
	}

	network := w.RemoteAddr().Network()
	a.metrics.ObserveQuery(network, req.Question[0].Qtype)

	if msg, ok := a.syntheticPTR(req); ok {
		a.metrics.syntheticPTRHits.Add(1)
		_ = w.WriteMsg(msg)
		return
	}

	client := a.udpClient
	if strings.HasPrefix(strings.ToLower(w.RemoteAddr().Network()), "tcp") {
		client = a.tcpClient
	}

	started := time.Now()
	resp, _, err := client.Exchange(req, a.upstream)
	a.metrics.ObserveUpstream(time.Since(started))
	if client == a.udpClient && err == nil && resp != nil && resp.Truncated {
		a.metrics.tcpFallbacks.Add(1)
		started = time.Now()
		resp, _, err = a.tcpClient.Exchange(req, a.upstream)
		a.metrics.ObserveUpstream(time.Since(started))
	}
	if err != nil || resp == nil {
		a.metrics.upstreamErrors.Add(1)
		logf("upstream failure: %v", err)
		dns.HandleFailed(w, req)
		return
	}

	if err := a.learn(req, resp); err != nil {
		logf("learning error: %v", err)
	}
	if err := w.WriteMsg(resp); err != nil {
		logf("write response: %v", err)
	}
}

func (a *App) syntheticPTR(req *dns.Msg) (*dns.Msg, bool) {
	q := req.Question[0]
	if q.Qtype != dns.TypePTR {
		return nil, false
	}
	ip := ptrNameToIP(q.Name)
	if ip == "" {
		return nil, false
	}
	name, ok, err := a.store.BestName(ip)
	if err != nil {
		logf("PTR lookup error: %v", err)
		return nil, false
	}
	if !ok {
		return nil, false
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = false
	m.Answer = append(m.Answer, &dns.PTR{
		Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: a.ptrTTL},
		Ptr: dns.Fqdn(name),
	})
	logf("SYNTH-PTR ip=%s name=%s", ip, name)
	return m, true
}

func (a *App) learn(req, resp *dns.Msg) error {
	qname := normalizeName(req.Question[0].Name)
	if strings.HasPrefix(qname, "_ta-") {
		return nil
	}

	cnames := map[string]cnameLink{}
	addresses := map[string][]ipRecord{}
	authorityNS := map[string]bool{}

	all := make([]dns.RR, 0, len(resp.Answer)+len(resp.Ns)+len(resp.Extra))
	all = append(all, resp.Answer...)
	all = append(all, resp.Ns...)
	all = append(all, resp.Extra...)

	for _, rr := range all {
		owner := normalizeName(rr.Header().Name)
		ttl := rr.Header().Ttl
		switch v := rr.(type) {
		case *dns.A:
			ip := v.A.String()
			addresses[owner] = append(addresses[owner], ipRecord{ip, ttl})
			if owner != qname {
				if err := a.store.LearnName(ip, owner, "answer", ttl); err != nil {
					return err
				}
			}
		case *dns.AAAA:
			ip := v.AAAA.String()
			addresses[owner] = append(addresses[owner], ipRecord{ip, ttl})
			if owner != qname {
				if err := a.store.LearnName(ip, owner, "answer", ttl); err != nil {
					return err
				}
			}
		case *dns.CNAME:
			cnames[owner] = cnameLink{normalizeName(v.Target), ttl}
			if err := a.store.LearnCNAME(owner, v.Target, ttl); err != nil {
				return err
			}
		case *dns.NS:
			if err := a.store.LearnAuthority(owner, v.Ns, ttl); err != nil {
				return err
			}
		case *dns.SOA:
			if err := a.store.LearnSOA(owner, v.Ns, ttl); err != nil {
				return err
			}
		case *dns.PTR:
			if ip := ptrNameToIP(owner); ip != "" {
				if err := a.store.LearnName(ip, v.Ptr, "ptr", ttl); err != nil {
					return err
				}
			}
		}
	}

	for _, rr := range resp.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			authorityNS[normalizeName(ns.Ns)] = true
		}
	}
	for _, rr := range resp.Extra {
		owner := normalizeName(rr.Header().Name)
		if !authorityNS[owner] {
			continue
		}
		switch v := rr.(type) {
		case *dns.A:
			if err := a.store.LearnName(v.A.String(), owner, "authority", rr.Header().Ttl); err != nil {
				return err
			}
		case *dns.AAAA:
			if err := a.store.LearnName(v.AAAA.String(), owner, "authority", rr.Header().Ttl); err != nil {
				return err
			}
		}
	}

	for ns := range authorityNS {
		if _, present := addresses[ns]; present {
			continue
		}
		go a.resolveAuthorityIPs(ns)
	}

	current := qname
	aliases := []string{qname}
	seen := map[string]bool{}
	for {
		link, ok := cnames[current]
		if !ok || seen[current] {
			break
		}
		seen[current] = true
		current = link.target
		aliases = append(aliases, current)
	}

	for _, rec := range addresses[current] {
		if err := a.store.LearnName(rec.ip, qname, "query", rec.ttl); err != nil {
			return err
		}
		for _, alias := range aliases[1:max(1, len(aliases)-1)] {
			if err := a.store.LearnName(rec.ip, alias, "cname", rec.ttl); err != nil {
				return err
			}
		}
		// Record the canonical (final) name in the CNAME chain at
		// "answer" priority. It is neither the queried name nor an
		// intermediate alias, so the loop above never stores it; without
		// this an AWS/CDN canonical name is dropped entirely.
		if current != qname {
			if err := a.store.LearnName(rec.ip, current, "answer", rec.ttl); err != nil {
				return err
			}
		}
		logf("LEARN query=%s ip=%s canonical=%s", qname, rec.ip, current)
	}
	return nil
}

func (a *App) resolveAuthorityIPs(ns string) {
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(ns), qtype)
		resp, _, err := a.udpClient.Exchange(m, a.upstream)
		if err == nil && resp != nil && resp.Truncated {
			resp, _, err = a.tcpClient.Exchange(m, a.upstream)
		}
		if err != nil || resp == nil {
			continue
		}
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				if err := a.store.LearnName(v.A.String(), ns, "authority", rr.Header().Ttl); err != nil {
					logf("authority A learn %s: %v", ns, err)
				}
			case *dns.AAAA:
				if err := a.store.LearnName(v.AAAA.String(), ns, "authority", rr.Header().Ttl); err != nil {
					logf("authority AAAA learn %s: %v", ns, err)
				}
			}
		}
	}
}

func ptrNameToIP(name string) string {
	name = normalizeName(name)
	if strings.HasSuffix(name, ".in-addr.arpa") {
		body := strings.TrimSuffix(name, ".in-addr.arpa")
		parts := strings.Split(body, ".")
		if len(parts) != 4 {
			return ""
		}
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		ip := net.ParseIP(strings.Join(parts, "."))
		if ip != nil {
			return ip.String()
		}
	}
	if strings.HasSuffix(name, ".ip6.arpa") {
		body := strings.TrimSuffix(name, ".ip6.arpa")
		nibbles := strings.Split(body, ".")
		if len(nibbles) != 32 {
			return ""
		}
		for i, j := 0, len(nibbles)-1; i < j; i, j = i+1, j-1 {
			nibbles[i], nibbles[j] = nibbles[j], nibbles[i]
		}
		hex := strings.Join(nibbles, "")
		var groups []string
		for i := 0; i < len(hex); i += 4 {
			groups = append(groups, hex[i:i+4])
		}
		ip := net.ParseIP(strings.Join(groups, ":"))
		if ip != nil {
			return ip.String()
		}
	}
	return ""
}

func main() {
	listen := flag.String("listen", "0.0.0.0:53", "DNS listen address")
	upstream := flag.String("upstream", "192.168.0.2:53", "upstream DNS server")
	dbPath := flag.String("database", defaultDB, "SQLite database path")
	ptrTTL := flag.Uint("ptr-ttl", defaultPTRTTL, "synthetic PTR TTL")
	httpListen := flag.String("http-listen", "127.0.0.1:8080", "HTTP status/API/metrics listen address; empty disables")
	jsonLog := flag.Bool("json-logs", false, "emit logs as one JSON object per line")
	flag.Parse()
	setJSONLogging(*jsonLog)

	store, err := NewStore(*dbPath)
	if err != nil {
		fatalf("database: %v", err)
	}
	defer store.Close()

	metrics := NewMetrics()
	app := NewApp(store, *upstream, uint32(*ptrTTL), metrics)
	udp := &dns.Server{Addr: *listen, Net: "udp", Handler: app}
	tcp := &dns.Server{Addr: *listen, Net: "tcp", Handler: app}

	errCh := make(chan error, 3)
	go func() { logf("PTRmaker UDP listening on %s", *listen); errCh <- udp.ListenAndServe() }()
	go func() { logf("PTRmaker TCP listening on %s", *listen); errCh <- tcp.ListenAndServe() }()

	var web *WebServer
	if *httpListen != "" {
		web = NewWebServer(*httpListen, store, metrics)
		go func() {
			logf("PTRmaker HTTP listening on %s", *httpListen)
			if err := web.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
				errCh <- err
			}
		}()
	}

	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for range t.C {
			if err := store.Cleanup(); err != nil {
				logf("cleanup: %v", err)
			}
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-sigCh:
		logf("shutting down on %s", sig)
	case err := <-errCh:
		if err != nil {
			logf("server stopped: %v", err)
		}
	}
	_ = udp.Shutdown()
	_ = tcp.Shutdown()
	if web != nil {
		_ = web.Shutdown()
	}
	fmt.Println("PTRmaker stopped")
}
