# 🐾 MeowMS — Advanced Microsoft Mail Checker

```
███╗   ███╗███████╗ ██████╗ ██╗    ██╗███╗   ███╗███████╗
████╗ ████║██╔════╝██╔═══██╗██║    ██║████╗ ████║██╔════╝
██╔████╔██║█████╗  ██║   ██║██║ █╗ ██║██╔████╔██║███████╗
██║╚██╔╝██║██╔══╝  ██║   ██║██║███╗██║██║╚██╔╝██║╚════██║
██║ ╚═╝ ██║███████╗╚██████╔╝╚███╔███╔╝██║ ╚═╝ ██║███████║
╚═╝     ╚═╝╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝     ╚═╝╚══════╝
```

> **High Performance Microsoft Account Checker**  
> Built in Go — 1000+ CPM · Multi-threaded · Proxy Support  
> *Created by Rivansoul & MeowMal Team*
> 
> ✈️ **Join Us on Telegram:**
> * **Channel:** [t.me/meowmalofficial](https://t.me/meowmalofficial)
> * **Community Group:** [t.me/meowmalgroup](https://t.me/meowmalgroup)

---

## 📁 Project Structure

```
MeowMS/
├── meow.go          # Main checker source (Go)
├── meow.exe         # Compiled binary (Windows)
├── config.ini       # Configuration file
├── acc.txt          # Account list (email:password)
├── proxies.txt      # Proxy list (one per line)
├── go.mod           # Go module definition
├── go.sum           # Go dependency checksums
└── Result/
    ├── ms.txt               # All valid hits
    ├── twofa.txt            # 2FA / blocked accounts
    ├── pts.txt              # Accounts with Rewards points
    ├── payment.txt          # Accounts with payment methods
    ├── cookies.zip          # Session cookies (ZIP archive containing individual .txt JSON files)
    ├── Inbox/               # Keyword inbox matches
    │   ├── steam.txt
    │   ├── minecraft.txt
    │   └── domains/         # Domain-filter matches
    │       ├── my.yorku.ca.txt
    │       └── uwaterloo.ca.txt
    └── country_sorted/      # Hits sorted by country
        ├── CA.txt
        ├── US.txt
        └── ...
```

---

## ⚙️ Configuration (`config.ini`)

```ini
[checker]
; Number of concurrent workers (150 default = 1k+ CPM)
threads = 150

; Retries per account on transient failures (0 = no retry)
retries = 2

[proxy]
file = proxies.txt

[inbox]
; Keywords to search in inbox
keywords = epicgames,steam,playstation,roblox,minecraft,paypal,crypto,amazon,netflix,spotify,binance,coinbase,discord

; Comma-separated sender domain filters
; Detects university/institution confirmation emails
domain_filter = @my.yorku.ca,@greatplainscollege.ca,@lakeheadu.ca,@mcmaster.ca,@sheridancollege.ca,@stclaircollege.ca,@torontomu.ca,@uottawa.ca,@uwaterloo.ca
```

---

## 📋 Input File Formats

### `acc.txt` — Account Combos
One account per line. Supports `:` or `;` separator:
```
email@outlook.com:password123
email@hotmail.com;mypassword
```

### `proxies.txt` — Proxy List
Supports HTTP, SOCKS4, and SOCKS5. One per line:
```
http://ip:port
socks5://ip:port
user:pass@ip:port
ip:port
```
> If `proxies.txt` is missing or empty, the checker runs in **proxyless mode**.

---

## 🚀 Usage

### Run the pre-built binary
```
meow.exe
```

### Build from source (requires Go 1.21+)
```bash
go build -o meow.exe .
```

---

## 📊 Output Legend

| Console Tag | Meaning |
|---|---|
| `[HIT]` (green) | Valid credentials — full capture logged |
| `[BAD]` (red) | Wrong email or password |
| `[2FA]` (yellow) | Account requires 2-factor auth / blocked |

### Hit line format
```
[20:14:33] [HIT] [CA] email@outlook.com | Name: John Doe | Country: CA | Rewards: 4520 pts | Payment: (1) active card | Inbox: [steam (3), minecraft (1)]
```

---

## 📂 Result Files

| File | Contents |
|---|---|
| `Result/ms.txt` | All valid hits (`email:pass`) |
| `Result/twofa.txt` | 2FA-locked accounts |
| `Result/pts.txt` | Accounts with Bing Rewards points |
| `Result/payment.txt` | Accounts with cards / PayPal |
| `Result/cookies.zip` | ZIP archive containing individual session cookies (one `<email>.txt` per account) |
| `Result/Inbox/<keyword>.txt` | Inbox keyword matches |
| `Result/Inbox/domains/<domain>.txt` | Domain-filter matches |
| `Result/country_sorted/<CC>.txt` | Hits sorted by country code |

---

## 🔍 Features

- **5-config login rotation** — Windows Chrome, Edge, Mac Chrome, Android, iPhone Safari
- **Fresh PPFT fallback** — automatic token refresh if all static configs fail
- **Bypass handlers** — auto-skips Microsoft proofs, privacy, and recovery interstitials
- **Rewards checker** — fetches Bing Rewards point balance
- **Payment checker** — detects active credit cards and PayPal accounts
- **Inbox searcher** — keyword + sender domain search via Outlook API
- **Cookie exporter** — saves authenticated session cookies as JSON inside a compressed ZIP folder (`.txt` per account)
- **Country sorting** — auto-sorts hits into per-country files
- **Dedup writer** — never writes the same account twice to any result file
- **Proxy manager** — rate-limit aware, auto-bans hot proxies temporarily
- **Crash-safe goroutines** — `recover()` on every worker; one bad account never kills the run
- **1000+ CPM** — 150 workers, short timeouts, GOMAXPROCS tuned

---

## ⚡ Performance Tuning

| Setting | Recommended |
|---|---|
| `threads` | 100–200 (scale with proxy count) |
| Proxy ratio | ~1 proxy per 3–5 threads |
| `retries` | 1–2 (higher = slower but more hits) |

> **Tip:** For maximum CPM, use a large rotating proxy pool (500+). Residential proxies give the best hit rate vs. datacenter proxies.

---

## 🛠️ Requirements

- **OS:** Windows (ANSI color + title bar support)
- **Go:** 1.21+ (only needed to build from source)
- **Dependencies:** `golang.org/x/net v0.24.0`

---

## 📝 Notes

- The checker auto-creates the `Result/` directory tree on first run.
- `config.ini` keywords **override** `inbox.txt` if both exist.
- Domain filters must start with `@` in config (e.g. `@uwaterloo.ca`) — the `@` is stripped automatically when querying Outlook's search API.
- Cookies are saved inside `Result/cookies.zip` as individual `<email>.txt` files containing a JSON list of cookies.

---

## ✈️ Community & Support

* **Telegram Channel:** [t.me/meowmalofficial](https://t.me/meowmalofficial) — updates, news, and official announcements.
* **Telegram Group:** [t.me/meowmalgroup](https://t.me/meowmalgroup) — support, chat, and community discussions.

---

*MeowMS v1.0 — MeowMal Dev's*
