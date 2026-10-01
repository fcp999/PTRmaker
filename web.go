package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

type Metrics struct {
	startedAt         time.Time
	queriesTotal      atomic.Uint64
	queriesUDP        atomic.Uint64
	queriesTCP        atomic.Uint64
	queriesA          atomic.Uint64
	queriesAAAA       atomic.Uint64
	queriesPTR        atomic.Uint64
	queriesOther      atomic.Uint64
	syntheticPTRHits  atomic.Uint64
	upstreamErrors    atomic.Uint64
	tcpFallbacks      atomic.Uint64
	upstreamRequests  atomic.Uint64
	upstreamLatencyNS atomic.Uint64
}

func NewMetrics() *Metrics { return &Metrics{startedAt: time.Now()} }

func (m *Metrics) ObserveQuery(network string, qtype uint16) {
	m.queriesTotal.Add(1)
	if strings.HasPrefix(strings.ToLower(network), "tcp") { m.queriesTCP.Add(1) } else { m.queriesUDP.Add(1) }
	switch qtype {
	case 1: m.queriesA.Add(1)
	case 28: m.queriesAAAA.Add(1)
	case 12: m.queriesPTR.Add(1)
	default: m.queriesOther.Add(1)
	}
}

func (m *Metrics) ObserveUpstream(d time.Duration) {
	m.upstreamRequests.Add(1)
	m.upstreamLatencyNS.Add(uint64(d))
}

type NameRecord struct {
	IP string `json:"ip"`
	Name string `json:"name"`
	Source string `json:"source"`
	FirstSeen int64 `json:"first_seen"`
	LastSeen int64 `json:"last_seen"`
	Expires int64 `json:"expires"`
	DNSTTL int64 `json:"dns_ttl"`
	Hits int64 `json:"hits"`
	Active bool `json:"active"`
}

type AuthorityRecord struct {
	Zone string `json:"zone"`
	Nameserver string `json:"nameserver"`
	LastSeen int64 `json:"last_seen"`
	Expires int64 `json:"expires"`
	DNSTTL int64 `json:"dns_ttl"`
	Hits int64 `json:"hits"`
	Active bool `json:"active"`
}

type DBCounts struct {
	Names int64 `json:"names"`
	ActiveNames int64 `json:"active_names"`
	Authorities int64 `json:"authorities"`
	CNAMEs int64 `json:"cnames"`
}

func (s *Store) LookupIP(ip string) ([]NameRecord, error) {
	now := time.Now().Unix()
	rows, err := s.db.Query(`SELECT ip,name,source,first_seen,last_seen,expires,dns_ttl,hits
FROM names WHERE ip=?
ORDER BY CASE source WHEN 'query' THEN 1 WHEN 'cname' THEN 2 WHEN 'answer' THEN 3 WHEN 'ptr' THEN 4 WHEN 'authority' THEN 5 ELSE 99 END,
last_seen DESC,hits DESC`, ip)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []NameRecord
	for rows.Next() {
		var r NameRecord
		if err := rows.Scan(&r.IP,&r.Name,&r.Source,&r.FirstSeen,&r.LastSeen,&r.Expires,&r.DNSTTL,&r.Hits); err != nil { return nil, err }
		r.Active = r.Expires >= now
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) RecentNames(limit int) ([]NameRecord, error) {
	if limit < 1 { limit = 25 }
	if limit > 500 { limit = 500 }
	now := time.Now().Unix()
	rows, err := s.db.Query(`SELECT ip,name,source,first_seen,last_seen,expires,dns_ttl,hits FROM names ORDER BY last_seen DESC LIMIT ?`, limit)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []NameRecord
	for rows.Next() {
		var r NameRecord
		if err := rows.Scan(&r.IP,&r.Name,&r.Source,&r.FirstSeen,&r.LastSeen,&r.Expires,&r.DNSTTL,&r.Hits); err != nil { return nil, err }
		r.Active = r.Expires >= now
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) RecentAuthorities(limit int) ([]AuthorityRecord, error) {
	if limit < 1 { limit = 25 }
	if limit > 500 { limit = 500 }
	now := time.Now().Unix()
	rows, err := s.db.Query(`SELECT zone,nameserver,last_seen,expires,dns_ttl,hits FROM authorities ORDER BY last_seen DESC LIMIT ?`, limit)
	if err != nil { return nil, err }
	defer rows.Close()
	var out []AuthorityRecord
	for rows.Next() {
		var r AuthorityRecord
		if err := rows.Scan(&r.Zone,&r.Nameserver,&r.LastSeen,&r.Expires,&r.DNSTTL,&r.Hits); err != nil { return nil, err }
		r.Active = r.Expires >= now
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) Counts() (DBCounts, error) {
	var c DBCounts
	now := time.Now().Unix()
	checks := []struct{ q string; p *int64; args []any }{
		{"SELECT COUNT(*) FROM names",&c.Names,nil},
		{"SELECT COUNT(*) FROM names WHERE expires>=?",&c.ActiveNames,[]any{now}},
		{"SELECT COUNT(*) FROM authorities",&c.Authorities,nil},
		{"SELECT COUNT(*) FROM cnames",&c.CNAMEs,nil},
	}
	for _, x := range checks {
		var err error
		if len(x.args)==0 { err=s.db.QueryRow(x.q).Scan(x.p) } else { err=s.db.QueryRow(x.q,x.args...).Scan(x.p) }
		if err != nil && err != sql.ErrNoRows { return c, err }
	}
	return c,nil
}

type WebServer struct { store *Store; metrics *Metrics; server *http.Server }

func NewWebServer(addr string, store *Store, metrics *Metrics) *WebServer {
	w:=&WebServer{store:store,metrics:metrics}
	mux:=http.NewServeMux()
	mux.HandleFunc("/",w.status)
	mux.HandleFunc("/healthz",w.health)
	mux.HandleFunc("/metrics",w.prometheus)
	mux.HandleFunc("/api/v1/lookup/",w.lookup)
	mux.HandleFunc("/api/v1/recent",w.recent)
	mux.HandleFunc("/api/v1/authorities",w.authorities)
	w.server=&http.Server{Addr:addr,Handler:mux,ReadHeaderTimeout:5*time.Second}
	return w
}
func (w *WebServer) ListenAndServe() error { return w.server.ListenAndServe() }
func (w *WebServer) Shutdown() error { return w.server.Close() }

func writeJSON(rw http.ResponseWriter,status int,v any) {
	rw.Header().Set("Content-Type","application/json")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(v)
}

func (w *WebServer) health(rw http.ResponseWriter,r *http.Request) {
	if r.URL.Path!="/healthz" { http.NotFound(rw,r); return }
	if err:=w.store.db.Ping(); err!=nil { writeJSON(rw,503,map[string]any{"status":"error","database":err.Error()}); return }
	writeJSON(rw,200,map[string]any{"status":"ok","uptime_sec":int64(time.Since(w.metrics.startedAt).Seconds())})
}

func (w *WebServer) lookup(rw http.ResponseWriter,r *http.Request) {
	raw:=strings.TrimPrefix(r.URL.Path,"/api/v1/lookup/")
	ip:=net.ParseIP(raw)
	if ip==nil { writeJSON(rw,400,map[string]string{"error":"invalid IP address"}); return }
	records,err:=w.store.LookupIP(ip.String())
	if err!=nil { writeJSON(rw,500,map[string]string{"error":err.Error()}); return }
	best,ok,err:=w.store.BestName(ip.String())
	if err!=nil { writeJSON(rw,500,map[string]string{"error":err.Error()}); return }
	writeJSON(rw,200,map[string]any{"ip":ip.String(),"best_name":best,"active_best":ok,"records":records})
}

func parseLimit(r *http.Request) int {
	n,err:=strconv.Atoi(r.URL.Query().Get("limit"))
	if err!=nil || n<1 { return 25 }
	if n>500 { return 500 }
	return n
}

func (w *WebServer) recent(rw http.ResponseWriter,r *http.Request) {
	x,err:=w.store.RecentNames(parseLimit(r))
	if err!=nil { writeJSON(rw,500,map[string]string{"error":err.Error()}); return }
	writeJSON(rw,200,x)
}
func (w *WebServer) authorities(rw http.ResponseWriter,r *http.Request) {
	x,err:=w.store.RecentAuthorities(parseLimit(r))
	if err!=nil { writeJSON(rw,500,map[string]string{"error":err.Error()}); return }
	writeJSON(rw,200,x)
}

func (w *WebServer) prometheus(rw http.ResponseWriter,r *http.Request) {
	c,_:=w.store.Counts()
	reqs:=w.metrics.upstreamRequests.Load()
	latNS:=w.metrics.upstreamLatencyNS.Load()
	avg:=0.0
	if reqs>0 { avg=float64(latNS)/float64(reqs)/1e9 }
	rw.Header().Set("Content-Type","text/plain; version=0.0.4")
	fmt.Fprintf(rw,"# TYPE ptrmaker_uptime_seconds gauge\nptrmaker_uptime_seconds %.0f\n",time.Since(w.metrics.startedAt).Seconds())
	fmt.Fprintf(rw,"# TYPE ptrmaker_dns_queries_total counter\nptrmaker_dns_queries_total %d\n",w.metrics.queriesTotal.Load())
	fmt.Fprintf(rw,"# TYPE ptrmaker_dns_queries_udp_total counter\nptrmaker_dns_queries_udp_total %d\n",w.metrics.queriesUDP.Load())
	fmt.Fprintf(rw,"# TYPE ptrmaker_dns_queries_tcp_total counter\nptrmaker_dns_queries_tcp_total %d\n",w.metrics.queriesTCP.Load())
	fmt.Fprintf(rw,"# TYPE ptrmaker_dns_queries_a_total counter\nptrmaker_dns_queries_a_total %d\n",w.metrics.queriesA.Load())
	fmt.Fprintf(rw,"# TYPE ptrmaker_dns_queries_aaaa_total counter\nptrmaker_dns_queries_aaaa_total %d\n",w.metrics.queriesAAAA.Load())
	fmt.Fprintf(rw,"# TYPE ptrmaker_dns_queries_ptr_total counter\nptrmaker_dns_queries_ptr_total %d\n",w.metrics.queriesPTR.Load())
	fmt.Fprintf(rw,"# TYPE ptrmaker_dns_queries_other_total counter\nptrmaker_dns_queries_other_total %d\n",w.metrics.queriesOther.Load())
	fmt.Fprintf(rw,"# TYPE ptrmaker_synthetic_ptr_hits_total counter\nptrmaker_synthetic_ptr_hits_total %d\n",w.metrics.syntheticPTRHits.Load())
	fmt.Fprintf(rw,"# TYPE ptrmaker_upstream_errors_total counter\nptrmaker_upstream_errors_total %d\n",w.metrics.upstreamErrors.Load())
	fmt.Fprintf(rw,"# TYPE ptrmaker_tcp_fallbacks_total counter\nptrmaker_tcp_fallbacks_total %d\n",w.metrics.tcpFallbacks.Load())
	fmt.Fprintf(rw,"# TYPE ptrmaker_upstream_requests_total counter\nptrmaker_upstream_requests_total %d\n",reqs)
	fmt.Fprintf(rw,"# TYPE ptrmaker_upstream_latency_seconds_avg gauge\nptrmaker_upstream_latency_seconds_avg %.9f\n",avg)
	fmt.Fprintf(rw,"# TYPE ptrmaker_db_names gauge\nptrmaker_db_names %d\n",c.Names)
	fmt.Fprintf(rw,"# TYPE ptrmaker_db_active_names gauge\nptrmaker_db_active_names %d\n",c.ActiveNames)
	fmt.Fprintf(rw,"# TYPE ptrmaker_db_authorities gauge\nptrmaker_db_authorities %d\n",c.Authorities)
	fmt.Fprintf(rw,"# TYPE ptrmaker_db_cnames gauge\nptrmaker_db_cnames %d\n",c.CNAMEs)
}

type statusData struct {
	Uptime string
	Counts DBCounts
	Queries uint64
	Synthetic uint64
	Errors uint64
	Fallbacks uint64
	Recent []NameRecord
	Authorities []AuthorityRecord
}

var statusTemplate=template.Must(template.New("status").Funcs(template.FuncMap{
	"ts":func(v int64)string{if v==0{return ""};return time.Unix(v,0).Format("2006-01-02 15:04:05")},
}).Parse(`<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="15"><title>PTRmaker</title>
<style>body{font-family:system-ui,sans-serif;margin:2rem;background:#111;color:#ddd}h1,h2{color:#fff}a{color:#7dd3fc}.cards{display:flex;gap:1rem;flex-wrap:wrap}.card{background:#1f2937;padding:1rem;border-radius:.6rem;min-width:10rem}.big{font-size:1.8rem;font-weight:700;color:#fff}table{border-collapse:collapse;width:100%;margin-bottom:2rem}th,td{text-align:left;padding:.45rem;border-bottom:1px solid #374151;font-size:.9rem}th{color:#9ca3af}.active{color:#86efac}.expired{color:#fca5a5}</style></head><body>
<h1>PTRmaker</h1><p>Learning DNS forwarder status. Uptime: <strong>{{.Uptime}}</strong> Â· <a href="/metrics">metrics</a> Â· <a href="/api/v1/recent">JSON</a> Â· <a href="/healthz">health</a></p>
<div class="cards"><div class="card"><div class="big">{{.Queries}}</div>DNS queries</div><div class="card"><div class="big">{{.Synthetic}}</div>Synthetic PTR hits</div><div class="card"><div class="big">{{.Counts.ActiveNames}}</div>Active names</div><div class="card"><div class="big">{{.Counts.Names}}</div>Historical mappings</div><div class="card"><div class="big">{{.Errors}}</div>Upstream errors</div><div class="card"><div class="big">{{.Fallbacks}}</div>TCP fallbacks</div></div>
<h2>Recent mappings</h2><table><tr><th>IP</th><th>Name</th><th>Source</th><th>Last seen</th><th>TTL</th><th>Hits</th><th>Status</th></tr>{{range .Recent}}<tr><td><a href="/api/v1/lookup/{{.IP}}">{{.IP}}</a></td><td>{{.Name}}</td><td>{{.Source}}</td><td>{{ts .LastSeen}}</td><td>{{.DNSTTL}}</td><td>{{.Hits}}</td><td>{{if .Active}}<span class="active">active</span>{{else}}<span class="expired">expired</span>{{end}}</td></tr>{{end}}</table>
<h2>Recent authorities</h2><table><tr><th>Zone</th><th>Name server</th><th>Last seen</th><th>TTL</th><th>Hits</th><th>Status</th></tr>{{range .Authorities}}<tr><td>{{.Zone}}</td><td>{{.Nameserver}}</td><td>{{ts .LastSeen}}</td><td>{{.DNSTTL}}</td><td>{{.Hits}}</td><td>{{if .Active}}<span class="active">active</span>{{else}}<span class="expired">expired</span>{{end}}</td></tr>{{end}}</table></body></html>`))

func (w *WebServer) status(rw http.ResponseWriter,r *http.Request) {
	if r.URL.Path!="/" { http.NotFound(rw,r); return }
	c,err:=w.store.Counts()
	if err!=nil { http.Error(rw,err.Error(),500); return }
	recent,_:=w.store.RecentNames(30)
	auth,_:=w.store.RecentAuthorities(20)
	d:=statusData{Uptime:time.Since(w.metrics.startedAt).Round(time.Second).String(),Counts:c,Queries:w.metrics.queriesTotal.Load(),Synthetic:w.metrics.syntheticPTRHits.Load(),Errors:w.metrics.upstreamErrors.Load(),Fallbacks:w.metrics.tcpFallbacks.Load(),Recent:recent,Authorities:auth}
	rw.Header().Set("Content-Type","text/html; charset=utf-8")
	if err:=statusTemplate.Execute(rw,d); err!=nil { logf("status page template: %v",err) }
}

var jsonLogs atomic.Bool
func setJSONLogging(v bool){jsonLogs.Store(v)}
func logf(format string,args ...any){
	msg:=fmt.Sprintf(format,args...)
	if jsonLogs.Load(){
		b,_:=json.Marshal(map[string]any{"time":time.Now().UTC().Format(time.RFC3339Nano),"level":"info","msg":msg})
		fmt.Fprintln(os.Stderr,string(b)); return
	}
	fmt.Fprintf(os.Stderr,"%s %s\n",time.Now().Format("2006/01/02 15:04:05"),msg)
}
func fatalf(format string,args ...any){logf(format,args...);os.Exit(1)}
