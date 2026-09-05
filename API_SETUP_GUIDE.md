# GhostBuster API Setup Guide 🔑

## Quick Start

All API keys are **optional** — ghostbuster works without them, but with keys you unlock:
- ✅ Shodan: Deep infrastructure scanning
- ✅ HIBP: Email breach history
- ✅ Multiple phone intel providers: Better accuracy

---

## 1️⃣ Shodan API Setup 🔍

**What it does:** Scans internet-facing infrastructure (ports, services, tech stack)

### Get Your Key:
1. Go to **https://account.shodan.io/**
2. Sign up or login
3. Navigate to **Account → API Key**
4. Copy your API key (looks like: `abc123def456...`)

### Add to Config:
```yaml
shodan_key: "your_shodan_api_key_here"
```

### Test It:
```bash
python3 ghostbuster.py 8.8.8.8 -c config.yaml
```

You'll see Shodan data in the **Infrastructure** panel ✅

---

## 2️⃣ Have I Been Pwned (HIBP) Setup 🔓

**What it does:** Checks if email appeared in known data breaches

### Get Your Key:
1. Go to **https://haveibeenpwned.com/API/Key**
2. Sign up (free tier available, paid for volume)
3. Verify email
4. Copy your API key

### Add to Config:
```yaml
hibp_key: "your_hibp_api_key_here"
```

### Test It:
```bash
python3 ghostbuster.py admin@example.com -c config.yaml
```

You'll see breach data in **Breach Exposure** panel ✅

---

## 3️⃣ Phone Intelligence APIs (Optional) 📱

Better phone number accuracy with multiple providers:

| Provider | Free Limit | Setup |
|----------|-----------|-------|
| **NumVerify** | 100/mo | https://numverify.com/ |
| **AbstractAPI** | 100/mo | https://app.abstractapi.com/ |
| **NumLookupAPI** | 100/mo | https://numlookupapi.com/ |
| **VeriPhone** | 1000/mo | https://veriphone.io/ |
| **IPQS** | 200/mo | https://ipqualityscore.com/ |
| **Twilio** | Trial | https://twilio.com/ |

### Add to Config:
```yaml
numverify_key: "your_key"
abstractapi_key: "your_key"
veriphone_key: "your_key"
ipqs_key: "your_key"
twilio_sid: "your_sid"
twilio_token: "your_token"
```

---

## Complete Config Example

```yaml
# GhostBuster Configuration

# Core APIs
shodan_key: "your_shodan_key_here"
hibp_key: "your_hibp_key_here"

# Phone providers (use at least 1-2 for better accuracy)
numverify_key: ""
abstractapi_key: ""
numlookupapi_key: ""
veriphone_key: ""
ipqs_key: ""
twilio_sid: ""
twilio_token: ""

# Proxy (if behind corporate firewall)
proxy: null  # "http://proxy.company.com:8080"

# Output settings
output_format: "json"  # json | xml | both
graph: false           # true for PNG relationship graphs

# Logging
log_level: "INFO"      # DEBUG | INFO | WARNING | ERROR
```

---

## 🚀 Usage Examples

### Email with Breach Check:
```bash
python3 ghostbuster.py admin@example.com -c config.yaml
```
**Shows:** Email split, domain, breach history from HIBP

### IP with Shodan:
```bash
python3 ghostbuster.py 1.1.1.1 -c config.yaml
```
**Shows:** Geo, ASN, **Shodan infrastructure data**, ports

### Phone with Multiple Providers:
```bash
python3 ghostbuster.py +919876543210 -c config.yaml
```
**Shows:** Validity, carrier, location, **consensus from 3+ providers**

### Bulk with All APIs:
```bash
python3 ghostbuster.py --bulk targets.txt -c config.yaml -f json
```
**Shows:** Full reconnaissance for all targets

---

## 💡 Tips & Tricks

✅ **Free tier strategy:**
- Use 1-2 paid APIs (Shodan + HIBP)
- Fill in free phone providers (NumVerify, VeriPhone, AbstractAPI)
- Rotate API keys if you hit limits

✅ **Privacy-first:**
- Phone numbers are masked in output (+919*********) 
- Reports safe for screenshots
- No data is logged beyond your machine

✅ **Performance:**
- Add `--log-level ERROR` to hide verbose output
- Use `-f json` for faster processing (no colored output)
- Bulk mode parallelizes all lookups

---

## 🔧 Troubleshooting

**"API key missing" error?**
```bash
# Make sure config.yaml is in same directory or use:
python3 ghostbuster.py target -c /path/to/config.yaml
```

**"Rate limited" errors?**
- You've hit API limits — wait before next request
- Upgrade to paid tier for more requests

**Want to disable a provider?**
- Just leave it empty: `shodan_key: ""`
- Ghostbuster auto-skips missing keys

---

## 📊 What Each API Unlocks

| API | IP | Domain | Email | Phone | URL |
|-----|-------|--------|-------|-------|-----|
| **Shodan** | ✅ ports/services | ✅ | ❌ | ❌ | ❌ |
| **HIBP** | ❌ | ❌ | ✅ breaches | ❌ | ❌ |
| **Phone APIs** | ❌ | ❌ | ❌ | ✅ validation | ❌ |

---

**Ready to maximize ghostbuster?** Copy the config and add your keys! 🔑
