// broadscan — internet-broad TCP scanner with an engagement scope gate.
//
//	connect scan (default, no privileges)  |  raw SYN scan (-syn, root)
//	streamed target expansion              |  scattered probe order (-shuffle)
//	banner grab on open ports              |  JSONL or plain output
//	scope file gate (-scope)               |  allow/deny CIDRs, deny wins
//
// build: make -C tools/broadscan
// run:   bin/broadscan -targets 1.2.3.0/24 -ports 22,80,443
//        bin/broadscan -syn -targets 10.0.0.0/8 -ports 1-1024 -rate 20000
//        bin/broadscan -targets 0.0.0.0/0 -ports 443 -scope scope.json -json
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// config
// ---------------------------------------------------------------------------

const (
	DefaultRate    = 2000                   // probes/sec
	DefaultTimeout = 900 * time.Millisecond // per probe
	DefaultWorkers = 256                    // connect-mode goroutines
	DefaultPorts   = "21,22,23,25,53,80,110,143,443,445,587,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017"
	ProgressEvery  = 5 * time.Second // stderr status line
	WindowBits     = 16              // shuffle unit = 64KiB address block
	WindowSize     = 1 << WindowBits
	BannerLimit    = 2048 // bytes read per banner
	BannerChars    = 200  // bytes kept per banner
	ShuffleMaxWin  = 1 << 20
	genBuffer      = 8192
)

// probes sent before reading a banner; empty = read-only
var probes = map[int][]byte{
	80:   []byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"),
	81:   []byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"),
	443:  nil,
	554:  []byte("OPTIONS rtsp://x/ RTSP/1.0\r\n\r\n"),
	6379: []byte("PING\r\n"),
	8000: []byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"),
	8080: []byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"),
	8081: []byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"),
	8888: []byte("HEAD / HTTP/1.0\r\nHost: x\r\n\r\n"),
}

type cfg struct {
	timeout time.Duration
	workers int
	banners bool
}

type hit struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Banner string `json:"banner,omitempty"`
	At     string `json:"at"`
}

type counters struct {
	sent int64
	open int64
}

// scopeFile is the gate handed to us by the caller (raphael bridge / brain).
// Nothing outside allow is ever probed; deny is subtracted from allow.
type scopeFile struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	var (
		targets = flag.String("targets", "", "CIDR, a.b.c.d-e or host, comma-separated, or a file of them")
		exclude = flag.String("exclude", "", "CIDR list or file to skip")
		ports   = flag.String("ports", DefaultPorts, "ports: 22,80,1000-2000")
		rate    = flag.Int("rate", DefaultRate, "probes per second")
		timeout = flag.Duration("timeout", DefaultTimeout, "per-probe timeout")
		workers = flag.Int("workers", DefaultWorkers, "connect-scan workers")
		out     = flag.String("out", "", "output file (default stdout)")
		asJSON  = flag.Bool("json", false, "JSONL output")
		banners = flag.Bool("banners", true, "grab banners on open ports")
		shuffle = flag.Bool("shuffle", true, "scatter probe order")
		syn     = flag.Bool("syn", false, "raw SYN scan (root required)")
		srcIP   = flag.String("src", "", "source IP for -syn (auto-detected)")
		scope   = flag.String("scope", "", "JSON scope gate {allow:[cidr],deny:[cidr]}")
		opsec   = flag.Bool("opsec", false, "opsec preset: raw syn, no banners, jitter, random ttl/window/sport")
		decoys  = flag.String("decoys", "", "decoy source CIDRs (spoofed SYN sources, syn mode)")
		decoyN  = flag.Int("decoy-n", 2, "decoys emitted per real probe")
		jitter  = flag.Duration("jitter", 0, "sleep up to this long before each probe (0=off)")
		ttlSet  = flag.String("ttl", "", "ttl or ttl range, e.g. 64 or 48-64")
		frag    = flag.Int("frag", 0, "fragment TCP header every N bytes (multiple of 8, 0=off)")
		sport   = flag.String("sport", "random", "source port strategy: random|fixed")
		tcpTS   = flag.Bool("tcp-ts", false, "add TCP timestamp option")
		stdinT  = flag.Bool("stdin", false, "read targets from stdin (one spec per line)")
		wipeSc  = flag.Bool("wipe-scope", false, "delete the -scope file after reading it")
	)
	flag.Parse()

	if *targets == "" && *stdinT {
		*targets = readStdinTargets()
	}
	if *targets == "" {
		flag.Usage()
		os.Exit(2)
	}

	// opsec preset: only the raw path can control TTL/window/decoys, and
	// banners make a full connection (an application-layer log line per hit).
	if *opsec {
		if !*syn {
			fatal("opsec: requires -syn (raw probes only)")
		}
		*banners = false
		if *jitter == 0 {
			*jitter = 25 * time.Millisecond
		}
		if *ttlSet == "" {
			*ttlSet = "48-64"
		}
	}
	// no core dumps: a crash must not leave process memory on disk
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0})

	ranges, err := parseTargets(*targets)
	if err != nil {
		fatal("targets: %v", err)
	}
	if len(ranges) == 0 {
		fatal("targets: nothing to scan")
	}
	ranges = mergeRanges(ranges)

	excl, err := parseTargets(*exclude)
	if err != nil {
		fatal("exclude: %v", err)
	}
	excl = mergeRanges(excl)

	var gate func(uint32) bool
	var allowRanges []ipRange
	if *scope != "" {
		sc, err := loadScope(*scope)
		if err != nil {
			fatal("scope: %v", err)
		}
		allow := parseScopeList(sc.Allow)
		deny := parseScopeList(sc.Deny)
		if len(allow) == 0 {
			fatal("scope: empty allow list")
		}
		allow = mergeRanges(allow)
		deny = mergeRanges(deny)
		allowRanges = allow

		ranges = mergeRanges(intersectRanges(ranges, allow))
		if len(ranges) == 0 {
			fatal("scope: every target is outside the allowed range")
		}
		excl = mergeRanges(append(excl, deny...))
		gate = func(ip uint32) bool { return !excluded(deny, ip) }
	}

	// opsec packet hygiene (raw path only)
	var ops *opsecConfig
	if *syn {
		ops = &opsecConfig{
			window:     *opsec || rand.Intn(2) == 0,
			timestamps: *tcpTS,
			fragSize:   *frag,
			fixedSport: *sport == "fixed",
			jitter:     *jitter,
			decoyN:     *decoyN,
		}
		if *ttlSet != "" {
			lo, hi, err := parseTTL(*ttlSet)
			if err != nil {
				fatal("ttl: %v", err)
			}
			ops.ttlLo, ops.ttlHi = lo, hi
		} else {
			ops.ttlLo, ops.ttlHi = 64, 64
		}
		if ops.fragSize != 0 && (ops.fragSize < 8 || ops.fragSize%8 != 0) {
			fatal("frag: must be a multiple of 8 (>= 8)")
		}
		if *decoys != "" {
			pool, err := parseTargets(*decoys)
			if err != nil {
				fatal("decoys: %v", err)
			}
			pool = mergeRanges(pool)
			if len(allowRanges) > 0 {
				for _, r := range pool {
					if len(intersectRanges([]ipRange{r}, allowRanges)) == 0 {
						fatal("decoys: %s is outside the allowed scope", u32ToIP(r.lo))
					}
				}
			}
			ops.decoys = pool
		}
		if *wipeSc {
			// scope file already read; leave nothing behind on disk
			_ = os.Remove(*scope)
		}
	}

	portList, err := parsePorts(*ports)
	if err != nil {
		fatal("ports: %v", err)
	}

	w, err := newWriter(*out, *asJSON)
	if err != nil {
		fatal("out: %v", err)
	}
	defer w.close()

	c := cfg{timeout: *timeout, workers: *workers, banners: *banners}
	if c.workers < 1 {
		c.workers = 1
	}

	st := &counters{}
	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		close(stop)
	}()

	lim := newLimiter(*rate)
	go progress(st, stop)

	ips := make(chan uint32, genBuffer)
	go genIPs(ranges, excl, *shuffle, gate, stop, ips)

	total := countAddrs(ranges, excl)
	if total == 0 {
		fatal("scope: no addresses left to probe after exclusions")
	}
	fmt.Fprintf(os.Stderr, "broadscan: %d addrs, %d ports, %d pps, mode=%s, scope=%s\n",
		total, len(portList), *rate, modeName(*syn), scopeName(*scope))

	start := time.Now()
	if *syn {
		if err := scanSYN(ips, portList, c, lim, st, w, *srcIP, ops, stop); err != nil {
			fatal("syn: %v", err)
		}
	} else {
		scanConnect(ips, portList, c, lim, st, w, stop)
	}

	el := time.Since(start).Seconds()
	pps := float64(atomic.LoadInt64(&st.sent)) / el
	fmt.Fprintf(os.Stderr, "\ndone: %d probed, %d open, %.0fs, %.0f pps\n",
		atomic.LoadInt64(&st.sent), atomic.LoadInt64(&st.open), el, pps)
}

func modeName(syn bool) string {
	if syn {
		return "syn"
	}
	return "connect"
}

func scopeName(p string) string {
	if p == "" {
		return "none"
	}
	return p
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "broadscan: "+f+"\n", a...)
	os.Exit(1)
}

// ---------------------------------------------------------------------------
// scope
// ---------------------------------------------------------------------------

func loadScope(path string) (scopeFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return scopeFile{}, err
	}
	var sc scopeFile
	if err := json.Unmarshal(b, &sc); err != nil {
		return scopeFile{}, fmt.Errorf("%s: %w", path, err)
	}
	return sc, nil
}

func parseScopeList(items []string) []ipRange {
	var out []ipRange
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		r, err := specToRange(s)
		if err != nil {
			fatal("scope: %q: %v", s, err)
		}
		out = append(out, r)
	}
	return out
}

func intersectRanges(a, b []ipRange) []ipRange {
	var out []ipRange
	for _, x := range a {
		for _, y := range b {
			lo, hi := x.lo, x.hi
			if y.lo > lo {
				lo = y.lo
			}
			if y.hi < hi {
				hi = y.hi
			}
			if lo <= hi {
				out = append(out, ipRange{lo, hi})
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// output
// ---------------------------------------------------------------------------

type writer struct {
	ch chan hit
	wg sync.WaitGroup
}

func newWriter(path string, asJSON bool) (*writer, error) {
	var f *os.File
	var err error
	if path == "" {
		f = os.Stdout
	} else {
		f, err = os.Create(path)
		if err != nil {
			return nil, err
		}
	}
	w := &writer{ch: make(chan hit, 4096)}
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		bw := bufio.NewWriterSize(f, 64<<10)
		if path != "" {
			// registered first so the flush below runs before the close
			defer f.Close()
		}
		defer bw.Flush()
		enc := json.NewEncoder(bw)
		for h := range w.ch {
			if asJSON {
				_ = enc.Encode(h)
			} else {
				if h.Banner != "" {
					fmt.Fprintf(bw, "%s:%d | %s\n", h.IP, h.Port, h.Banner)
				} else {
					fmt.Fprintf(bw, "%s:%d\n", h.IP, h.Port)
				}
			}
		}
	}()
	return w, nil
}

func (w *writer) send(h hit) { w.ch <- h }
func (w *writer) close()     { close(w.ch); w.wg.Wait() }

func progress(st *counters, stop <-chan struct{}) {
	t := time.NewTicker(ProgressEvery)
	defer t.Stop()
	var last int64
	var lastT = time.Now()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			now := time.Now()
			sent := atomic.LoadInt64(&st.sent)
			open := atomic.LoadInt64(&st.open)
			pps := float64(sent-last) / now.Sub(lastT).Seconds()
			fmt.Fprintf(os.Stderr, "\r%12d probed  %6d open  %8.0f pps", sent, open, pps)
			last, lastT = sent, now
		}
	}
}

// ---------------------------------------------------------------------------
// rate limit
// ---------------------------------------------------------------------------

type limiter struct {
	mu     sync.Mutex
	rate   float64
	tokens float64
	last   time.Time
}

func newLimiter(rate int) *limiter {
	if rate < 1 {
		rate = 1
	}
	r := float64(rate)
	return &limiter{rate: r, tokens: r, last: time.Now()}
}

func (l *limiter) wait() {
	for {
		l.mu.Lock()
		now := time.Now()
		l.tokens += now.Sub(l.last).Seconds() * l.rate
		l.last = now
		if l.tokens > l.rate {
			l.tokens = l.rate
		}
		if l.tokens >= 1 {
			l.tokens--
			l.mu.Unlock()
			return
		}
		need := (1 - l.tokens) / l.rate
		l.mu.Unlock()
		d := time.Duration(need * float64(time.Second))
		if d < 50*time.Microsecond {
			d = 50 * time.Microsecond
		}
		time.Sleep(d)
	}
}

// ---------------------------------------------------------------------------
// targets
// ---------------------------------------------------------------------------

type ipRange struct{ lo, hi uint32 }

func parseTargets(spec string) ([]ipRange, error) {
	if spec == "" {
		return nil, nil
	}
	var items []string
	if st, err := os.Stat(spec); err == nil && !st.IsDir() {
		f, err := os.Open(spec)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			if i := strings.IndexByte(line, '#'); i >= 0 {
				line = line[:i]
			}
			line = strings.TrimSpace(line)
			if line != "" {
				items = append(items, line)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	} else {
		items = strings.Split(spec, ",")
	}

	var out []ipRange
	for _, raw := range items {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		r, err := specToRange(s)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", s, err)
		}
		out = append(out, r)
	}
	return out, nil
}

func specToRange(s string) (ipRange, error) {
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return ipRange{}, err
		}
		lo := ipToU32(n.IP.To4())
		ones, bits := n.Mask.Size()
		if bits != 32 {
			return ipRange{}, errors.New("not IPv4")
		}
		var mask uint32
		if ones > 0 {
			mask = ^uint32(0) << (32 - ones)
		}
		hi := lo | ^mask
		if ones == 0 {
			hi = 0xffffffff
		}
		return ipRange{lo, hi}, nil
	}
	if i := strings.LastIndexByte(s, '-'); i > 0 {
		loIP := net.ParseIP(strings.TrimSpace(s[:i])).To4()
		if loIP == nil {
			return ipRange{}, errors.New("bad start address")
		}
		lo := ipToU32(loIP)
		right := strings.TrimSpace(s[i+1:])
		if strings.Contains(right, ".") {
			hiIP := net.ParseIP(right).To4()
			if hiIP == nil {
				return ipRange{}, errors.New("bad end address")
			}
			hi := ipToU32(hiIP)
			if hi < lo {
				return ipRange{}, errors.New("range inverted")
			}
			return ipRange{lo, hi}, nil
		}
		n, err := strconv.Atoi(right)
		if err != nil || n < 0 || n > 255 {
			return ipRange{}, errors.New("bad last octet")
		}
		hi := (lo & 0xffffff00) | uint32(n)
		if hi < lo {
			return ipRange{}, errors.New("range inverted")
		}
		return ipRange{lo, hi}, nil
	}
	ip := net.ParseIP(s).To4()
	if ip == nil {
		return ipRange{}, errors.New("bad address")
	}
	v := ipToU32(ip)
	return ipRange{v, v}, nil
}

func mergeRanges(in []ipRange) []ipRange {
	if len(in) == 0 {
		return nil
	}
	sort.Slice(in, func(i, j int) bool { return in[i].lo < in[j].lo })
	out := []ipRange{in[0]}
	for _, r := range in[1:] {
		last := &out[len(out)-1]
		if r.lo <= last.hi || last.hi == 0xffffffff || r.lo == last.hi+1 {
			if r.hi > last.hi {
				last.hi = r.hi
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

func countAddrs(ranges, excl []ipRange) uint64 {
	var n, m uint64
	for _, r := range ranges {
		n += uint64(r.hi) - uint64(r.lo) + 1
	}
	// only count exclusions that actually fall inside the target ranges
	for _, e := range excl {
		for _, r := range ranges {
			lo, hi := e.lo, e.hi
			if r.lo > lo {
				lo = r.lo
			}
			if r.hi < hi {
				hi = r.hi
			}
			if lo <= hi {
				m += uint64(hi) - uint64(lo) + 1
			}
		}
	}
	if m >= n {
		return 0
	}
	return n - m
}

func excluded(excl []ipRange, ip uint32) bool {
	i := sort.Search(len(excl), func(i int) bool { return excl[i].hi >= ip })
	return i < len(excl) && excl[i].lo <= ip
}

func ipToU32(b net.IP) uint32 { return binary.BigEndian.Uint32(b[0:4]) }

func u32ToIP(v uint32) net.IP {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return net.IP(b[:])
}

// ---------------------------------------------------------------------------
// generator
// ---------------------------------------------------------------------------

func genIPs(ranges, excl []ipRange, shuffle bool, gate func(uint32) bool, stop <-chan struct{}, out chan<- uint32) {
	defer close(out)
	for _, r := range ranges {
		if stopped(stop) {
			return
		}
		if shuffle {
			emitShuffled(r, excl, gate, stop, out)
		} else {
			emitSequential(r, excl, gate, stop, out)
		}
	}
}

func stopped(stop <-chan struct{}) bool {
	select {
	case <-stop:
		return true
	default:
		return false
	}
}

func allowed(gate func(uint32) bool, v uint32) bool {
	return gate == nil || gate(v)
}

func emitSequential(r ipRange, excl []ipRange, gate func(uint32) bool, stop <-chan struct{}, out chan<- uint32) {
	for ip := uint64(r.lo); ip <= uint64(r.hi); ip++ {
		if stopped(stop) {
			return
		}
		v := uint32(ip)
		if excluded(excl, v) || !allowed(gate, v) {
			continue
		}
		out <- v
	}
}

func emitShuffled(r ipRange, excl []ipRange, gate func(uint32) bool, stop <-chan struct{}, out chan<- uint32) {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() ^ int64(r.lo)))

	firstWin := r.lo >> WindowBits
	lastWin := r.hi >> WindowBits
	wins := uint64(lastWin) - uint64(firstWin) + 1

	order := func(i uint64) uint32 { return uint32(firstWin + uint32(i)) }

	emitWin := func(w uint32) bool {
		wlo := w << WindowBits
		lo := wlo
		if lo < r.lo {
			lo = r.lo
		}
		hi := wlo | (WindowSize - 1)
		if hi > r.hi {
			hi = r.hi
		}
		odd := rnd.Uint32() | 1
		salt := rnd.Uint32()
		for i := uint32(0); i < WindowSize; i++ {
			if stopped(stop) {
				return false
			}
			v := wlo + (((i * odd) + salt) & (WindowSize - 1))
			if v < lo || v > hi {
				continue
			}
			if excluded(excl, v) || !allowed(gate, v) {
				continue
			}
			out <- v
		}
		return true
	}

	if wins <= ShuffleMaxWin {
		perm := make([]uint64, wins)
		for i := range perm {
			perm[i] = uint64(i)
		}
		rnd.Shuffle(len(perm), func(i, j int) { perm[i], perm[j] = perm[j], perm[i] })
		for _, i := range perm {
			if !emitWin(order(i)) {
				return
			}
		}
		return
	}

	// huge space: sequential window walk, scattered inside each window
	for i := uint64(0); i < wins; i++ {
		if !emitWin(order(i)) {
			return
		}
	}
}

// ---------------------------------------------------------------------------
// ports
// ---------------------------------------------------------------------------

func parsePorts(spec string) ([]int, error) {
	seen := map[int]bool{}
	for _, part := range strings.Split(spec, ",") {
		p := strings.TrimSpace(part)
		if p == "" {
			continue
		}
		if i := strings.IndexByte(p, '-'); i > 0 {
			lo, err1 := strconv.Atoi(strings.TrimSpace(p[:i]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(p[i+1:]))
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || hi < lo {
				return nil, fmt.Errorf("bad range %q", p)
			}
			for x := lo; x <= hi; x++ {
				seen[x] = true
			}
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("bad port %q", p)
		}
		seen[n] = true
	}
	out := make([]int, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Ints(out)
	if len(out) == 0 {
		return nil, errors.New("no ports")
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// connect scan
// ---------------------------------------------------------------------------

func scanConnect(ips <-chan uint32, ports []int, c cfg, lim *limiter, st *counters, w *writer, stop <-chan struct{}) {
	var wg sync.WaitGroup
	for i := 0; i < c.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: c.timeout}
			for ip := range ips {
				if stopped(stop) {
					continue
				}
				host := u32ToIP(ip).String()
				for _, p := range ports {
					lim.wait()
					atomic.AddInt64(&st.sent, 1)
					conn, err := d.Dial("tcp4", net.JoinHostPort(host, strconv.Itoa(p)))
					if err != nil {
						continue
					}
					b := ""
					if c.banners {
						b = grab(conn, p, c.timeout)
					}
					_ = conn.Close()
					atomic.AddInt64(&st.open, 1)
					w.send(hit{IP: host, Port: p, Banner: b, At: time.Now().UTC().Format(time.RFC3339)})
				}
			}
		}()
	}
	wg.Wait()
}

func grab(conn net.Conn, port int, timeout time.Duration) string {
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if probe, ok := probes[port]; ok && len(probe) > 0 {
		_, _ = conn.Write(probe)
	}
	buf := make([]byte, BannerLimit)
	n, _ := conn.Read(buf)
	return cleanBanner(buf[:n])
}

func cleanBanner(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c == '\n' || c == '\t' {
			sb.WriteByte(' ')
			continue
		}
		if c < 0x20 || c > 0x7e {
			sb.WriteByte('.')
			continue
		}
		sb.WriteByte(c)
	}
	s := strings.TrimSpace(sb.String())
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	if len(s) > BannerChars {
		s = s[:BannerChars]
	}
	return s
}

// ---------------------------------------------------------------------------
// syn scan
// ---------------------------------------------------------------------------

type pendingKey uint64

type probeMeta struct {
	at  time.Time
	src net.IP
}

func key(sport, dport uint16) pendingKey { return pendingKey(uint64(dport)<<16 | uint64(sport)) }

// routeSource returns the address the kernel would use to reach dst.
func routeSource(dst net.IP) net.IP {
	c, err := net.Dial("udp4", net.JoinHostPort(dst.String(), "9"))
	if err != nil {
		return nil
	}
	defer c.Close()
	ua, ok := c.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil
	}
	return ua.IP.To4()
}

func scanSYN(ips <-chan uint32, ports []int, c cfg, lim *limiter, st *counters, w *writer, explicitSrc string, ops *opsecConfig, stop <-chan struct{}) error {
	explicit := net.IP(nil)
	if explicitSrc != "" {
		ip := net.ParseIP(explicitSrc).To4()
		if ip == nil {
			return errors.New("source ip: not an IPv4 address")
		}
		explicit = ip
	}
	defaultSrc, err := sourceIP("")
	if err != nil {
		return fmt.Errorf("source ip: %w", err)
	}

	sendFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("raw socket (need root): %w", err)
	}
	defer syscall.Close(sendFd)
	if err := syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("IP_HDRINCL: %w", err)
	}

	recvFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return fmt.Errorf("recv socket: %w", err)
	}
	defer syscall.Close(recvFd)
	bindIP := net.IPv4zero.To4()
	if explicit != nil {
		bindIP = explicit
	}
	var sa4 [4]byte
	copy(sa4[:], bindIP)
	if err := syscall.Bind(recvFd, &syscall.SockaddrInet4{Addr: sa4}); err != nil {
		return fmt.Errorf("bind %s: %w", bindIP, err)
	}
	tv := syscall.Timeval{Sec: 0, Usec: 200000}
	if err := syscall.SetsockoptTimeval(recvFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("SO_RCVTIMEO: %w", err)
	}

	var pend sync.Map // pendingKey -> probeMeta
	var srcCache sync.Map // dst>>8 -> net.IP
	var done atomic.Bool

	// receiver
	go func() {
		buf := make([]byte, 4096)
		for !done.Load() {
			n, _, err := syscall.Recvfrom(recvFd, buf, 0)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK || err == syscall.EINTR {
					continue
				}
				return
			}
			if n < 40 {
				continue
			}
			p := buf[:n]
			ihl := int(p[0]&0x0f) * 4
			if ihl < 20 || len(p) < ihl+20 {
				continue
			}
			if p[9] != 6 {
				continue
			}
			tcp := p[ihl:]
			sport := binary.BigEndian.Uint16(tcp[0:2])
			dport := binary.BigEndian.Uint16(tcp[2:4])
			flags := tcp[13]
			// reply: sport is the port we probed, dport is our source port
			k := key(dport, sport)
			v, ok := pend.Load(k)
			if !ok {
				continue
			}
			meta := v.(probeMeta)
			switch {
			case flags&0x12 == 0x12: // SYN|ACK
				pend.Delete(k)
				host := net.IP(p[12:16]).String()
				atomic.AddInt64(&st.open, 1)
				port := int(sport)
				b := ""
				if c.banners {
					b = grabDial(host, port, c.timeout)
				}
				w.send(hit{IP: host, Port: port, Banner: b, At: time.Now().UTC().Format(time.RFC3339)})
				// tear the half-open down politely
				sendRST(sendFd, meta.src, net.IP(p[12:16]).To4(), sport, dport,
					binary.BigEndian.Uint32(tcp[8:12]))
			case flags&0x04 != 0: // RST
				pend.Delete(k)
			}
		}
	}()

	// expiry
	go func() {
		ttl := c.timeout * 3
		for !done.Load() {
			time.Sleep(200 * time.Millisecond)
			now := time.Now()
			pend.Range(func(k, v any) bool {
				if now.Sub(v.(probeMeta).at) > ttl {
					pend.Delete(k)
				}
				return true
			})
		}
	}()

	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	for ip := range ips {
		if stopped(stop) {
			break
		}
		dst := u32ToIP(ip).To4()
		src := explicit
		if src == nil {
			if v, ok := srcCache.Load(ip >> 8); ok {
				src = v.(net.IP)
			} else {
				src = routeSource(dst)
				if src == nil {
					src = defaultSrc
				}
				srcCache.Store(ip>>8, src)
			}
		}
		for _, port := range ports {
			lim.wait()
			ops.jitterSleep()
			sport := ops.pickSport()
			seq := rnd.Uint32()
			pkt := buildSYNSeg(src, dst, sport, uint16(port), seq,
				ops.pickTTL(), ops.pickWindow(), ops.timestamps)
			sa := &syscall.SockaddrInet4{}
			copy(sa.Addr[:], dst)
			k := key(sport, uint16(port))
			// arm before sending: loopback replies can arrive in microseconds
			pend.Store(k, probeMeta{at: time.Now(), src: src})
			if err := sendFrags(sendFd, pkt, ops.fragSize, sa); err != nil {
				pend.Delete(k)
				continue
			}
			atomic.AddInt64(&st.sent, 1)
			// decoys: spoofed sources, replies are never tracked
			for i := 0; i < ops.decoyN; i++ {
				dip, ok := ops.pickDecoy(ip)
				if !ok {
					break
				}
				dpkt := buildSYNSeg(u32ToIP(dip).To4(), dst, ops.pickSport(),
					uint16(port), rand.Uint32(),
					ops.pickTTL(), ops.pickWindow(), ops.timestamps)
				_ = sendFrags(sendFd, dpkt, ops.fragSize, sa)
			}
		}
	}

	// drain replies
	deadline := time.Now().Add(c.timeout * 3)
	for time.Now().Before(deadline) {
		empty := true
		pend.Range(func(_, _ any) bool { empty = false; return false })
		if empty {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	done.Store(true)
	return nil
}

func sendFrags(fd int, pkt []byte, size int, sa *syscall.SockaddrInet4) error {
	for _, f := range fragmentPacket(pkt, size) {
		if err := syscall.Sendto(fd, f, 0, sa); err != nil {
			return err
		}
	}
	return nil
}

func parseTTL(s string) (uint8, uint8, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '-'); i > 0 {
		lo, err1 := strconv.Atoi(strings.TrimSpace(s[:i]))
		hi, err2 := strconv.Atoi(strings.TrimSpace(s[i+1:]))
		if err1 != nil || err2 != nil || lo < 1 || hi > 255 || hi < lo {
			return 0, 0, fmt.Errorf("bad range %q", s)
		}
		return uint8(lo), uint8(hi), nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 255 {
		return 0, 0, fmt.Errorf("bad value %q", s)
	}
	return uint8(n), uint8(n), nil
}

func readStdinTargets() string {
	var parts []string
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		if line = strings.TrimSpace(line); line != "" {
			parts = append(parts, line)
		}
	}
	return strings.Join(parts, ",")
}

func grabDial(host string, port int, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort(host, strconv.Itoa(port)), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	return grab(conn, port, timeout)
}

func sourceIP(explicit string) (net.IP, error) {
	if explicit != "" {
		ip := net.ParseIP(explicit).To4()
		if ip == nil {
			return nil, errors.New("not an IPv4 address")
		}
		return ip, nil
	}
	c, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	defer c.Close()
	ip := c.LocalAddr().(*net.UDPAddr).IP.To4()
	if ip == nil {
		return nil, errors.New("no IPv4 route")
	}
	return ip, nil
}

func buildSYN(src, dst net.IP, sport, dport uint16, seq uint32) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	binary.BigEndian.PutUint16(pkt[4:6], uint16(rand.Uint32()))
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000) // DF
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[0:20]))

	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], sport)
	binary.BigEndian.PutUint16(tcp[2:4], dport)
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	tcp[12] = 5 << 4
	tcp[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcp[14:16], 64240)

	ph := make([]byte, 0, 32)
	ph = append(ph, src.To4()...)
	ph = append(ph, dst.To4()...)
	ph = append(ph, 0, 6)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(tcp)))
	ph = append(ph, l[:]...)
	binary.BigEndian.PutUint16(tcp[16:18], checksum(append(ph, tcp...)))
	return pkt
}

func sendRST(fd int, src, dst net.IP, sport, dport uint16, ack uint32) {
	pkt := buildSYN(src, dst, sport, dport, ack)
	pkt[20+13] = 0x04 // RST
	binary.BigEndian.PutUint32(pkt[20+8:20+12], ack)
	binary.BigEndian.PutUint16(pkt[20+16:20+18], 0)
	ph := make([]byte, 0, 32)
	ph = append(ph, src.To4()...)
	ph = append(ph, dst.To4()...)
	ph = append(ph, 0, 6, 0, 20)
	binary.BigEndian.PutUint16(pkt[20+16:20+18], checksum(append(ph, pkt[20:]...)))
	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], dst.To4())
	_ = syscall.Sendto(fd, pkt, 0, sa)
}

func checksum(b []byte) uint16 {
	var s uint32
	for i := 0; i+1 < len(b); i += 2 {
		s += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		s += uint32(b[len(b)-1]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xffff) + (s >> 16)
	}
	return ^uint16(s)
}
