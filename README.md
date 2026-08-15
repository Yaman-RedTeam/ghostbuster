# 👻 GhostBuster

> **Open-Source Intelligence (OSINT) Reconnaissance Framework**  
> By [Yaman RedTeam](https://github.com/Yaman-RedTeam) | Authorized Penetration Testing Only

```
  ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗
 ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
 ██║  ███╗███████║██║   ██║███████╗   ██║   
 ██║   ██║██╔══██║██║   ██║╚════██║   ██║   
 ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   
  ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝  
 ██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ 
 ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
 ██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝
 ██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗
 ██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║
 ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
```

---

## ⚠️ Legal Disclaimer

**GhostBuster is intended for authorized security research, bug bounty programs, and penetration testing engagements only.**

- Use only on systems you own or have explicit written permission to test
- The author assumes NO responsibility for unauthorized or illegal use
- Misuse of this tool may violate computer crime laws in your jurisdiction
- Always comply with applicable laws and regulations

---

## Features

| Module | Capabilities |
|--------|-------------|
| 🌐 **IP Intel** | Geolocation, ASN, VPN/Proxy/Tor detection, reverse DNS, Shodan integration |
| 📞 **Phone Intel** | International parsing, carrier ID, region, line type (mobile/VoIP/landline) |
| 🔗 **Domain Forensics** | DNS records, WHOIS/RDAP, SSL cert transparency, subdomain enum, Wayback Machine, tech fingerprinting |
| 🔍 **URL Analysis** | Shortener expansion with full redirect chains, domain deep-dive |
| 👤 **Identity OSINT** | Username enumeration across 24+ platforms, email permutations, HIBP breach check |
| 🖼️ **Image Intel** | EXIF extraction, GPS coordinates → Google Maps link |
| 📊 **Graph Output** | Visual relationship graphs (networkx + matplotlib) |

---

## Installation

```bash
git clone https://github.com/Yaman-RedTeam/ghostbuster
cd ghostbuster
pip install -r requirements.txt
```

**Optional — enhanced results with API keys:**
- [Shodan](https://account.shodan.io/) — exposed ports, banners, CVEs
- [HaveIBeenPwned](https://haveibeenpwned.com/API/Key) — breach database

Add keys to `config.yaml`.

---

## Usage

### Single Target

```bash
# IP Investigation
python ghostbuster.py investigate ip 1.2.3.4

# Domain Recon
python ghostbuster.py investigate domain example.com

# URL Expansion + Domain Intel
python ghostbuster.py investigate url https://bit.ly/abc123

# Username Enumeration (24+ platforms)
python ghostbuster.py investigate username target_handle

# Email Breach Check
python ghostbuster.py investigate email target@example.com

# Phone Number Analysis
python ghostbuster.py investigate phone +911234567890

# Image EXIF / GPS Extraction
python ghostbuster.py investigate image photo.jpg
```

### Bulk Processing

```bash
# From a text file (auto-detects type per line)
python ghostbuster.py bulk targets.txt

# CSV format: type,value
python ghostbuster.py bulk targets.csv --format both --graph
```

### Options

```
-c / --config     Config file path (default: config.yaml)
-o / --output     Output file base name (default: ghostbuster_report)
-f / --format     json | xml | both
--graph           Generate relationship graph PNG
--log-level       DEBUG | INFO | WARNING | ERROR
```

---

## Output

- **JSON** — structured findings, all raw data with source attribution
- **XML** — same data in XML format for integration
- **PNG graph** — visual map of discovered relationships (with `--graph`)

Example JSON structure:
```json
{
  "meta": { "generated": "...", "tool": "GhostBuster OSINT Framework" },
  "results": [
    {
      "target": { "type": "domain", "value": "example.com" },
      "data": {
        "dns": { "A": [...], "MX": [...], "TXT": [...] },
        "whois": { "registrar": "...", "registered": "..." },
        "subdomains": ["sub1.example.com", "sub2.example.com"],
        "tech": { "server": "nginx", "frameworks": ["WordPress"] }
      }
    }
  ]
}
```

---

## Bulk File Format

**TXT** (auto-type detection):
```
192.168.1.1
example.com
https://bit.ly/xyz
user@example.com
+911234567890
someusername
```

**CSV**:
```csv
type,value
ip,1.2.3.4
domain,example.com
username,johndoe
```

---

## Configuration (`config.yaml`)

```yaml
shodan_key: "YOUR_SHODAN_KEY"
hibp_key: "YOUR_HIBP_KEY"
proxy: null              # "http://host:port" or "socks5://host:port"
output_format: "json"
graph: false
log_level: "INFO"
```

---

## Related Projects

- [👻 ghostphish](https://github.com/Yaman-RedTeam/ghostphish) — Phishing simulation framework for authorized red team engagements

---

## License

MIT License — see [LICENSE](LICENSE)

**Use responsibly. Stay legal. Happy hunting. 👻**
