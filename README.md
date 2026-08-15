<div align="center">

# 👻 GhostBuster

### `OSINT Reconnaissance Framework`

**_Hunt every ghost in the machine._**

```
   ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓ ▄▄▄▄    █    ██   ██████ ▄▄▄█████▓▓█████  ██▀███
  ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒▓█████▄  ██  ▓██▒▒██    ▒ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
 ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░▒██▒ ▄██▓██  ▒██░░ ▓██▄   ▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒
 ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░ ▒██░█▀  ▓▓█  ░██░  ▒   ██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄
 ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░ ░▓█  ▀█▓▒▒█████▓ ▒██████▒▒  ▒██▒ ░ ░▒████▒░██▓ ▒██▒
  ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░   ░▒▓███▀▒░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░  ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░
```

[![Version](https://img.shields.io/badge/version-1.0.0-brightgreen?style=for-the-badge&logo=semver)]()
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white)]()
[![License](https://img.shields.io/badge/license-MIT-orange?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Termux-black?style=for-the-badge&logo=linux&logoColor=white)]()
[![Status](https://img.shields.io/badge/status-active-success?style=for-the-badge)]()

[![Author](https://img.shields.io/badge/Author-Yaman.RedTeam-red?style=for-the-badge&logo=hackthebox&logoColor=white)](https://github.com/Yaman-RedTeam)
[![Instagram](https://img.shields.io/badge/-Instagram-E4405F?style=for-the-badge&logo=instagram&logoColor=white)](https://instagram.com/Yaman.RedTeam)
[![YouTube](https://img.shields.io/badge/-YouTube-FF0000?style=for-the-badge&logo=youtube&logoColor=white)](https://youtube.com/@YamanRedTeam)

**One framework — seven intelligence modules — every artifact correlated.**

</div>

---

## ⚠️ Legal Disclaimer

> **GhostBuster is a defensive-focused OSINT tool. Use ONLY for authorized security research, bug bounty programs, and penetration testing engagements.**
>
> - ✅ Use only on systems you own or have **explicit written permission** to test
> - ❌ The author assumes **NO responsibility** for unauthorized or illegal use
> - ⚖️ Misuse may violate computer crime laws — you alone are accountable
> - 📜 Always comply with local laws, GDPR, and platform ToS

---

## 🎯 What It Does

GhostBuster is a **modular reconnaissance framework** that fuses seven OSINT disciplines into a single async pipeline. Feed it an artifact (IP, domain, email, phone, image, URL, username), and it returns a **correlated JSON/XML report** — optionally with a **visual relationship graph** — in seconds.

Built for red teamers, bug bounty hunters, threat intel analysts, and DFIR practitioners who need answers fast without babysitting ten different tools.

---

## 🧭 The Honest-Intelligence Principle

> **GhostBuster's core rule: never present a guess as a fact.**

Most phone-OSINT tools happily print a `Carrier` field and call it a day. The problem — that field is almost always **wrong** in markets with Mobile Number Portability (MNP). GhostBuster is built to know the difference between *what it can prove* and *what it's guessing*, and to **say so out loud**.

Every finding is sorted into one of three confidence tiers:

| Tier | Meaning | Example fields |
|------|---------|----------------|
| ✅ **Verified** | Algorithmically certain or MNP-proof | Validity, line type, number formats, **telecom circle / state** |
| ⚠️ **Stale-risk** | Real data, but may be out of date | `Carrier (current)` from a live API — labelled with its source |
| ❌ **Unknowable (free)** | No free/legal source can determine this | Live carrier of a ported number, GPS coordinates |

### What this looks like in practice

GhostBuster was hardened against **real Indian numbers**, and each edge case taught it to be more honest:

- **Number ported to a new operator (MNP)** → shows `Carrier (current): Jio` from a live provider **and** `↳ MNP: ported — originally Airtel`. It never conflates the *original allocation* (from static number-series data) with the *current network*.
- **Provider names a defunct operator** (e.g. Aircel, shut down 2018) → GhostBuster refuses to parrot it: `Carrier (current): unknown — definitely ported`, with a `↳ why` note. A dead operator provably can't be the current one.
- **Jio / pan-India series** (numbers not bound to a geographic circle) → the built-in geocoder's guess is **suppressed**: `Region: unknown (Jio/MNP number — not geo-bound)`, rather than confidently printing a wrong city.
- **Circle-bound legacy series** (older Airtel/Vodafone/BSNL) → resolves reliably to the **state/circle** (e.g. *UP East*), marked `✓ reliable (MNP-proof)`, because the circle is intrinsic to the number series and survives porting.

### Why circle (state) is trustworthy but carrier isn't

An Indian mobile number's **first four digits** encode the telecom **circle** it was originally allocated in. MNP lets you change *operator*, but **not** your number — so the circle stays valid for the life of the number. That's why GhostBuster reports **state/region with confidence** while treating **current carrier as best-effort**.

### The multi-provider consensus engine

For fields it *can* improve, GhostBuster runs every configured provider in parallel and **votes**:

- **Validity & line type** — majority vote across all sources → confidence %.
- **Carrier** — resolved from **live API providers only** (they track ported numbers); static offline data is kept *separately* as "original allocation" so it can't drag a correct answer into a false dispute.

More provider keys = higher confidence and better tie-breaking. Zero keys still works — you just get the offline tier with honest "add a key for live data" prompts.

> **Bottom line:** if GhostBuster prints it as a fact, you can cite it. If it's a guess, it's labelled a guess. That's the whole philosophy.

---

## ✨ Feature Matrix

<table>
<tr>
  <th align="left">Module</th>
  <th align="left">Capabilities</th>
  <th align="center">API-key<br/>Boost</th>
</tr>

<tr>
  <td>🌐 <b>IP Intelligence</b></td>
  <td>Geolocation • ASN & org lookup • VPN/Proxy/Tor detection • Reverse DNS • Shodan port/CVE mapping</td>
  <td align="center">Shodan</td>
</tr>

<tr>
  <td>🔗 <b>Domain Forensics</b></td>
  <td>Full DNS records (A/AAAA/MX/TXT/NS/SOA) • WHOIS/RDAP • SSL cert transparency • Passive subdomain enum • Wayback Machine • Tech fingerprinting</td>
  <td align="center">—</td>
</tr>

<tr>
  <td>🔍 <b>URL Analysis</b></td>
  <td>Shortener expansion with full redirect chain • Landing-page domain deep-dive • Header/security analysis</td>
  <td align="center">—</td>
</tr>

<tr>
  <td>👤 <b>Identity OSINT</b></td>
  <td>Username enumeration across <b>24+ platforms</b> • Email permutation generator • HaveIBeenPwned breach lookup</td>
  <td align="center">HIBP</td>
</tr>

<tr>
  <td>📞 <b>Phone Intelligence</b></td>
  <td>International parsing (E.164) • Carrier identification • Region/country • Line type (mobile/VoIP/landline)</td>
  <td align="center">—</td>
</tr>

<tr>
  <td>🖼️ <b>Image Intelligence</b></td>
  <td>EXIF metadata extraction • GPS coordinates → Google Maps link • Camera fingerprinting</td>
  <td align="center">—</td>
</tr>

<tr>
  <td>📊 <b>Graph Correlation</b></td>
  <td>NetworkX-powered relationship graph • PNG export • Cross-artifact linking (IP ↔ domain ↔ user ↔ email)</td>
  <td align="center">—</td>
</tr>

</table>

---

## 🚀 Quickstart

### Installation

**Recommended — one-shot installer (handles Kali PEP 668, Termux, Linux/macOS):**

```bash
git clone https://github.com/Yaman-RedTeam/ghostbuster
cd ghostbuster
chmod +x install.sh
./install.sh
```

<details>
<summary><b>Manual install (per-platform)</b></summary>

**Kali / Debian / Ubuntu (system-wide, works with other pentest tools):**
```bash
sudo apt install -y python3-aiohttp python3-phonenumbers python3-exifread \
                    python3-networkx python3-matplotlib python3-yaml
pip install -r requirements.txt --break-system-packages
```

**Termux:**
```bash
pkg install python rust
pip install -r requirements.txt
```

**macOS / plain Linux (isolated venv):**
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

</details>

> ⚠️ **Kali users:** don't use `venv` unless you know why — GhostBuster is designed to sit alongside your other CLI tools (nmap, sqlmap, etc.). System-wide install keeps everything on the same PATH.

### Optional API keys (enhanced results)

| Service | Free tier | What it unlocks |
|---------|-----------|-----------------|
| [Shodan](https://account.shodan.io/) | ✅ | Exposed ports, service banners, CVE mapping |
| [HaveIBeenPwned](https://haveibeenpwned.com/API/Key) | 💰 | Full breach database lookup |

Drop keys into `config.yaml` — GhostBuster auto-detects and enables the modules.

---

## ⚡ Usage

### 🎯 Simple mode — just pass a value, type is auto-detected

```bash
ghostbuster 1.2.3.4                    # → IP intel
ghostbuster example.com                # → domain forensics
ghostbuster https://bit.ly/abc123      # → URL expansion + recon
ghostbuster +911234567890              # → phone OSINT
ghostbuster user@example.com           # → email breach check
ghostbuster photo.jpg                  # → EXIF / GPS
ghostbuster johndoe                    # → username hunt (24+ platforms)
```

### 🎛️ Explicit mode — force a type (useful for ambiguous inputs)

```bash
ghostbuster --type username johndoe
ghostbuster phone +911234567890        # positional form also works
```

### 📦 Bulk mode

```bash
ghostbuster --bulk targets.txt                          # auto-type per line
ghostbuster --bulk targets.csv --format both --graph    # CSV + graph PNG
```

---

## 📸 Sample Output — Phone Intel

A real run against an Indian mobile (a Veriphone key is set, so the live-carrier tier is active):

```console
$ ghostbuster +9193358XXXXX

   ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓ ▄▄▄▄    █    ██   ██████ ▄▄▄█████▓▓█████  ██▀███
  ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒▓█████▄  ██  ▓██▒▒██    ▒ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
        ┌──────────────────────────────────────────────────────────┐
        │  👻 GhostBuster • OSINT Reconnaissance Framework • v1.0.0 │
        │  Developed by Yaman.RedTeam • Authorized Testing Only     │
        └──────────────────────────────────────────────────────────┘

╭──────────────────── Intelligence Profile ────────────────────╮
│    Number  +9193358XXXXX                                     │
│   Country  🇮🇳  India (IN · +91)                              │
│      Type  mobile                                            │
│  Validity  VALID                                            │
│   Carrier  (original allocation, pre-MNP)                   │
│  Timezone  Asia/Calcutta                                    │
╰──────────────────────────────────────────────────────────────╯
╭──────────────────── Location Intelligence ───────────────────╮
│                Circle  📍 UP East ✓ reliable (MNP-proof)     │
│  Operator (at launch)  Airtel — NOT the current carrier      │
│               Country  India (IN)                            │
╰──────────────────────────────────────────────────────────────╯
╭─────────────── Messenger Presence & Pivots ──────────────────╮
│  Whatsapp  ✓ reachable  (200)                                │
│  Telegram  ✓ reachable  (200)                                │
╰──────────────────────────────────────────────────────────────╯
╭───────── ⚡ VERIFIED FACTS  (what we can trust) ─────────────╮
│           Validity  VALID  ██████████ 100%                   │
│          Line Type  mobile  ██████████ 100%                  │
│  Carrier (current)  Jio  ██████████ 100%  via veriphone      │
│              ↳ MNP  ported — originally Airtel               │
╰──────────────────────────────────────────────────────────────╯
╭──────────────────── Provider Status ─────────────────────────╮
│    offline  ● ran      1 ms                                  │
│  veriphone  ● ran   2696 ms                                  │
╰──────────────────────────────────────────────────────────────╯
```

Notice the honest-intelligence tiers in action: **circle** is `✓ reliable`, the **live carrier** (Jio) is separated from the **original allocation** (Airtel) with an explicit `ported` note, and nothing is presented as fact that the free tier can't actually prove.

<details>
<summary><b>Edge case: a number reporting a defunct operator</b></summary>

```console
$ ghostbuster +918565XXXXXX

╭───────── ⚡ VERIFIED FACTS  (what we can trust) ─────────────╮
│           Validity  VALID  ██████████ 100%                   │
│          Line Type  mobile  ██████████ 100%                  │
│  Carrier (current)  unknown — definitely ported             │
│              ↳ why  veriphone says 'Aircel (defunct)' —      │
│                     that operator is shut down              │
╰──────────────────────────────────────────────────────────────╯
```

Aircel shut down in 2018, so the number provably **cannot** be on Aircel now — GhostBuster refuses to parrot the stale answer and reports the truth: *definitely ported, current network unknowable from free sources.*

</details>

---

## 🎛️ CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --type` | Force target type (skip auto-detect) | auto |
| `-b, --bulk` | Bulk-process file (CSV/JSON/TXT) | — |
| `-c, --config` | Config file path | `config.yaml` |
| `-o, --output` | Output basename | `ghostbuster_report` |
| `-f, --format` | `json` \| `xml` \| `both` | `json` |
| `--graph` | Render relationship PNG | off |
| `--log-level` | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` | `INFO` |

---

## 📦 Output Formats

- **JSON** — structured findings with source attribution
- **XML** — same data, XML-native (for SIEM/IR pipelines)
- **PNG graph** — visual relationship map (`--graph`)

<details>
<summary>📄 <b>Example JSON structure</b></summary>

```json
{
  "meta": {
    "generated": "2026-08-15T09:00:00Z",
    "tool": "GhostBuster OSINT Framework",
    "version": "1.0.0"
  },
  "results": [
    {
      "target": { "type": "domain", "value": "example.com" },
      "data": {
        "dns": { "A": ["93.184.216.34"], "MX": [...], "TXT": [...] },
        "whois": { "registrar": "IANA", "registered": "1995-08-14" },
        "subdomains": ["www.example.com", "api.example.com"],
        "tech": { "server": "nginx", "frameworks": ["Bootstrap"] },
        "certs": [{ "issuer": "DigiCert", "expires": "..." }]
      }
    }
  ]
}
```

</details>

---

## 📥 Bulk File Formats

<details>
<summary><b>TXT — auto-type detection</b></summary>

```
192.168.1.1
example.com
https://bit.ly/xyz
user@example.com
+911234567890
someusername
```

</details>

<details>
<summary><b>CSV — explicit typing</b></summary>

```csv
type,value
ip,1.2.3.4
domain,example.com
username,johndoe
email,test@example.com
phone,+15551234567
```

</details>

---

## ⚙️ Configuration

`config.yaml`:

```yaml
shodan_key: "YOUR_SHODAN_KEY"        # optional
hibp_key:   "YOUR_HIBP_KEY"          # optional
proxy:      null                      # e.g. "socks5://127.0.0.1:9050"
output_format: "json"
graph:      false
log_level:  "INFO"
```

Copy `config.example.yaml` → `config.yaml` and drop your keys in.

---

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────┐
│              GhostBuster CLI (argparse)           │
└──────────────────────┬────────────────────────────┘
                       │
        ┌──────────────▼──────────────┐
        │      GhostBusterEngine (async)    │
        │  • Task dispatch            │
        │  • Rate-limit + retry       │
        │  • SQLite cache             │
        └──────────────┬──────────────┘
                       │
   ┌────┬────┬────┬────┼────┬────┬────┬────┐
   ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼
  IP  Domain URL User Mail Phone Image Graph Report
```

- **Async everywhere** — aiohttp + asyncio for parallel fan-out
- **SQLite cache** — repeated lookups return in ms, not seconds
- **Modular modules** — add a new intel type without touching the engine

---

## 🔗 Related Projects

- 👻 **[ghostphish](https://github.com/Yaman-RedTeam/ghostphish)** — Phishing simulation framework for authorized red team engagements

---

## 🤝 Contributing

Pull requests welcome for new intel modules, additional platforms in username enum, or performance improvements. Open an issue first for major changes.

---

## 📜 License

**MIT License** — see [LICENSE](LICENSE)

---

<div align="center">

### 🕶️ _Use responsibly. Stay legal. Happy hunting._

**Crafted with 🖤 by [Yaman.RedTeam](https://github.com/Yaman-RedTeam)**

`If it walks like a ghost and talks like a ghost — GhostBuster will find it.`

</div>
