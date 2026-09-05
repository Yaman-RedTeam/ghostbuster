# GhostBuster Interactive Mode 🎯

## New Feature: Interactive Menu

When you run `ghostbuster` **without any arguments**, it now shows an interactive menu!

### Launch Interactive Mode

```bash
python3 ghostbuster.py
```

You'll see:

```
Choose a reconnaissance type:

1 📱 Phone Number
   Analyze phone numbers, carriers, location, MNP status

2 🌍 IP Address
   GeoIP lookup, ASN, reverse DNS, infrastructure

3 🔗 Domain
   WHOIS, DNS, subdomains, SSL certificates

4 📧 Email Address
   Email parsing, breach checking (HIBP)

5 🔍 Username
   Find social media profiles, linked accounts

6 🌐 Website URL
   URL expansion, redirects, domain analysis

7 🖼️ Image File
   EXIF metadata, geolocation, camera info

8 📊 Bulk Scan
   Scan multiple targets from file (CSV/JSON/TXT)

Enter choice (1-8) or 'q' to quit:
```

---

## How It Works

### Step 1: Choose Type
Select 1-8 based on what you want to scan

### Step 2: Enter Target
```
Enter Phone Number target: +919876543210
```

The tool will then analyze your target and show results!

---

## Examples

### Interactive: Phone Analysis
```
1                          # Choose option 1
+919876543210              # Enter phone number
```

### Interactive: IP Lookup
```
2                          # Choose option 2
8.8.8.8                    # Enter IP address
```

### Interactive: Domain Scan
```
3                          # Choose option 3
example.com                # Enter domain
```

### Interactive: Bulk Scan
```
8                          # Choose option 8
targets.txt                # Enter file path
```

---

## Command-Line Mode (Still Available)

You can still use command-line mode like before:

```bash
# Auto-detect type
python3 ghostbuster.py +919876543210

# Explicit type
python3 ghostbuster.py phone +919876543210

# Bulk scan
python3 ghostbuster.py --bulk targets.txt

# With config
python3 ghostbuster.py 8.8.8.8 -c config.yaml

# With output format
python3 ghostbuster.py admin@example.com -f json
```

---

## Input Validation

The interactive mode validates inputs:
- ✅ Handles empty input (cancels gracefully)
- ✅ Validates menu choices (1-8 or 'q')
- ✅ Works with Ctrl+C (keyboard interrupt)
- ✅ Loops until valid choice or quit

---

## Configuration

Interactive mode uses:
- Default config: `config.yaml`
- Default output: `ghostbuster_report`
- Default format: `json`
- Log level: `INFO`

To customize, use command-line mode:
```bash
python3 ghostbuster.py -c custom_config.yaml -f both -o my_report
```

---

## Benefits

🎯 **Beginner-friendly**: No need to remember flags
🎯 **Interactive**: Real-time target input
🎯 **Clear options**: Descriptions for each type
🎯 **Flexible**: Still supports CLI for automation
🎯 **Educational**: Learn OSINT step-by-step

---

## Keyboard Shortcuts

- **q** → Quit gracefully
- **Ctrl+C** → Force exit
- **Enter** → Cancel current operation

---

**Try it now:** `python3 ghostbuster.py` 🚀
