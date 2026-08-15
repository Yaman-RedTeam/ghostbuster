#!/usr/bin/env python3
"""
GhostBuster — OSINT Reconnaissance Framework
Authorized penetration testing and open-source intelligence tool.
By Yaman RedTeam | github.com/Yaman-RedTeam/ghostbuster
"""

import asyncio
import aiohttp
import argparse
import json
import logging
import logging.handlers
import sqlite3
import sys
import re
import socket
import ipaddress
import csv
import yaml
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import Optional, Any
from urllib.parse import urlparse, urljoin
import subprocess

try:
    import exifread
    EXIF_AVAILABLE = True
except ImportError:
    EXIF_AVAILABLE = False

try:
    import networkx as nx
    import matplotlib.pyplot as plt
    GRAPH_AVAILABLE = True
except ImportError:
    GRAPH_AVAILABLE = False

try:
    import phonenumbers
    from phonenumbers import geocoder, carrier, number_type
    PHONE_AVAILABLE = True
except ImportError:
    PHONE_AVAILABLE = False

# ─── Logging Setup ──────────────────────────────────────────────────────────

def setup_logging(log_file: str = "ghostbuster.log", level: str = "INFO"):
    logger = logging.getLogger("ghostbuster")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    fh = logging.handlers.RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    return logger

log = setup_logging()

# ─── Cache (SQLite) ──────────────────────────────────────────────────────────

class Cache:
    def __init__(self, db_path: str = "ghostbuster_cache.db"):
        self.conn = sqlite3.connect(db_path)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                key TEXT PRIMARY KEY,
                value TEXT,
                ts REAL
            )
        """)
        self.conn.commit()

    def get(self, key: str, ttl: int = 3600) -> Optional[Any]:
        row = self.conn.execute(
            "SELECT value, ts FROM cache WHERE key=?", (key,)
        ).fetchone()
        if row and (datetime.now().timestamp() - row[1]) < ttl:
            return json.loads(row[1] if False else row[0])
        return None

    def set(self, key: str, value: Any):
        self.conn.execute(
            "INSERT OR REPLACE INTO cache VALUES (?,?,?)",
            (key, json.dumps(value), datetime.now().timestamp())
        )
        self.conn.commit()

cache = Cache()

# ─── HTTP Session Factory ─────────────────────────────────────────────────────

def make_headers() -> dict:
    return {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/json,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

async def fetch(session: aiohttp.ClientSession, url: str, **kwargs) -> Optional[Any]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15),
                               ssl=False, **kwargs) as r:
            ct = r.headers.get("Content-Type", "")
            if "json" in ct:
                return await r.json(content_type=None)
            return await r.text()
    except Exception as e:
        log.debug(f"fetch error {url}: {e}")
        return None

# ─── Module 1: IP & Infrastructure Intelligence ───────────────────────────────

class IPIntel:
    """IP geolocation, ASN, VPN/proxy detection, reverse DNS."""

    @staticmethod
    def extract_ips(text: str) -> list[str]:
        pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        candidates = re.findall(pattern, text)
        valid = []
        for ip in candidates:
            try:
                obj = ipaddress.ip_address(ip)
                if not obj.is_private and not obj.is_loopback:
                    valid.append(ip)
            except ValueError:
                pass
        return list(set(valid))

    @staticmethod
    async def geolocate(session: aiohttp.ClientSession, ip: str) -> dict:
        cached = cache.get(f"geo:{ip}")
        if cached:
            return cached

        data = await fetch(session, f"https://ipinfo.io/{ip}/json")
        result = {}
        if isinstance(data, dict):
            result = {
                "ip": ip,
                "hostname": data.get("hostname"),
                "city": data.get("city"),
                "region": data.get("region"),
                "country": data.get("country"),
                "loc": data.get("loc"),
                "org": data.get("org"),
                "asn": data.get("org", "").split()[0] if data.get("org") else None,
                "timezone": data.get("timezone"),
            }
        cache.set(f"geo:{ip}", result)
        return result

    @staticmethod
    async def check_proxy_vpn(session: aiohttp.ClientSession, ip: str) -> dict:
        cached = cache.get(f"proxy:{ip}")
        if cached:
            return cached
        data = await fetch(session, f"https://proxycheck.io/v2/{ip}?vpn=1&asn=1")
        result = {}
        if isinstance(data, dict) and ip in data:
            entry = data[ip]
            result = {
                "proxy": entry.get("proxy") == "yes",
                "vpn": entry.get("type") in ("VPN", "TOR"),
                "type": entry.get("type"),
                "provider": entry.get("provider"),
                "asn": entry.get("asn"),
                "isp": entry.get("isp"),
            }
        cache.set(f"proxy:{ip}", result)
        return result

    @staticmethod
    async def reverse_dns(ip: str) -> list[str]:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return [hostname]
        except Exception:
            return []

    @staticmethod
    async def shodan_lookup(session: aiohttp.ClientSession, ip: str, api_key: str) -> dict:
        if not api_key:
            return {"error": "No Shodan API key configured"}
        cached = cache.get(f"shodan:{ip}")
        if cached:
            return cached
        data = await fetch(session, f"https://api.shodan.io/shodan/host/{ip}?key={api_key}")
        result = {}
        if isinstance(data, dict) and "error" not in data:
            result = {
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "os": data.get("os"),
                "vulns": list(data.get("vulns", {}).keys()),
                "services": [
                    {"port": s.get("port"), "product": s.get("product"),
                     "version": s.get("version"), "banner": s.get("data", "")[:200]}
                    for s in data.get("data", [])
                ],
            }
        cache.set(f"shodan:{ip}", result)
        return result

# ─── Module 2: Phone Number Intelligence ─────────────────────────────────────

class PhoneIntel:
    """Phone parsing, carrier, geo, line type."""

    @staticmethod
    def analyze(raw: str) -> dict:
        if not PHONE_AVAILABLE:
            return {"error": "phonenumbers library not installed"}
        try:
            parsed = phonenumbers.parse(raw, None)
            if not phonenumbers.is_valid_number(parsed):
                return {"error": "Invalid phone number"}
            ntype = number_type(parsed)
            type_map = {
                phonenumbers.PhoneNumberType.MOBILE: "mobile",
                phonenumbers.PhoneNumberType.FIXED_LINE: "landline",
                phonenumbers.PhoneNumberType.VOIP: "voip",
                phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
                phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
            }
            return {
                "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
                "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
                "country_code": parsed.country_code,
                "national_number": parsed.national_number,
                "carrier": carrier.name_for_number(parsed, "en"),
                "region": geocoder.description_for_number(parsed, "en"),
                "line_type": type_map.get(ntype, "unknown"),
                "valid": True,
            }
        except Exception as e:
            return {"error": str(e)}

# ─── Module 3: Domain & URL Forensics ────────────────────────────────────────

class DomainIntel:
    """WHOIS, DNS, SSL certs, subdomain enum, URL expansion, Wayback."""

    SHORTENERS = {
        "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd",
        "buff.ly", "adf.ly", "goo.gl", "shorte.st", "cutt.ly",
    }

    @staticmethod
    async def expand_url(session: aiohttp.ClientSession, url: str) -> dict:
        chain = [url]
        current = url
        try:
            for _ in range(10):
                async with session.head(
                    current, allow_redirects=False,
                    timeout=aiohttp.ClientTimeout(total=10), ssl=False
                ) as r:
                    loc = r.headers.get("Location")
                    if loc and loc != current:
                        if loc.startswith("/"):
                            parsed = urlparse(current)
                            loc = f"{parsed.scheme}://{parsed.netloc}{loc}"
                        chain.append(loc)
                        current = loc
                    else:
                        break
        except Exception as e:
            log.debug(f"URL expand error: {e}")
        return {"original": url, "final": chain[-1], "chain": chain}

    @staticmethod
    async def dns_lookup(domain: str) -> dict:
        result = {}
        try:
            result["A"] = [str(r) for r in socket.getaddrinfo(domain, None, socket.AF_INET)]
        except Exception:
            result["A"] = []
        # Extended records via dig if available
        for rtype in ["MX", "TXT", "NS", "CNAME"]:
            try:
                proc = await asyncio.create_subprocess_exec(
                    "dig", "+short", rtype, domain,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
                )
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
                result[rtype] = out.decode().strip().splitlines()
            except Exception:
                result[rtype] = []
        return result

    @staticmethod
    async def whois_lookup(session: aiohttp.ClientSession, domain: str) -> dict:
        cached = cache.get(f"whois:{domain}")
        if cached:
            return cached
        data = await fetch(session, f"https://rdap.org/domain/{domain}")
        result = {}
        if isinstance(data, dict):
            result = {
                "registrar": next(
                    (e.get("fn") for e in data.get("entities", [])
                     if "registrar" in e.get("roles", [])), None
                ),
                "registered": next(
                    (e.get("value") for e in data.get("events", [])
                     if e.get("eventAction") == "registration"), None
                ),
                "expiry": next(
                    (e.get("value") for e in data.get("events", [])
                     if e.get("eventAction") == "expiration"), None
                ),
                "nameservers": [ns.get("ldhName") for ns in data.get("nameservers", [])],
                "status": data.get("status", []),
            }
        cache.set(f"whois:{domain}", result)
        return result

    @staticmethod
    async def cert_transparency(session: aiohttp.ClientSession, domain: str) -> list[str]:
        cached = cache.get(f"crt:{domain}")
        if cached:
            return cached
        data = await fetch(session, f"https://crt.sh/?q=%.{domain}&output=json")
        subdomains = set()
        if isinstance(data, list):
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.splitlines():
                    sub = sub.strip().lstrip("*.")
                    if sub.endswith(domain):
                        subdomains.add(sub)
        result = sorted(subdomains)
        cache.set(f"crt:{domain}", result)
        return result

    @staticmethod
    async def wayback_lookup(session: aiohttp.ClientSession, domain: str, limit: int = 20) -> list[dict]:
        url = (f"https://web.archive.org/cdx/search/cdx?url={domain}/*"
               f"&output=json&limit={limit}&fl=timestamp,original,statuscode&collapse=digest")
        data = await fetch(session, url)
        if not isinstance(data, list) or len(data) < 2:
            return []
        headers = data[0]
        return [dict(zip(headers, row)) for row in data[1:]]

    @staticmethod
    async def tech_fingerprint(session: aiohttp.ClientSession, url: str) -> dict:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as r:
                headers = dict(r.headers)
                body = await r.text()
        except Exception as e:
            return {"error": str(e)}

        tech = {}
        server = headers.get("Server", "")
        if server:
            tech["server"] = server
        powered = headers.get("X-Powered-By", "")
        if powered:
            tech["powered_by"] = powered

        patterns = {
            "WordPress": r"wp-content|wp-includes|wordpress",
            "Joomla": r"joomla|/components/com_",
            "Drupal": r"drupal|/sites/default/",
            "Laravel": r"laravel_session|csrf-token.*laravel",
            "Django": r"csrfmiddlewaretoken|djdt",
            "React": r"react\.production\.min\.js|__REACT",
            "Angular": r"ng-version|angular\.js",
            "Vue.js": r"vue\.runtime|__vue__",
            "Bootstrap": r"bootstrap\.min\.css|bootstrap\.bundle",
        }
        detected = []
        for name, pat in patterns.items():
            if re.search(pat, body, re.IGNORECASE):
                detected.append(name)
        tech["frameworks"] = detected

        og = {}
        for tag in re.findall(r'<meta[^>]+property=["\']og:([^"\']+)["\'][^>]*content=["\']([^"\']+)["\']', body, re.IGNORECASE):
            og[tag[0]] = tag[1]
        tech["og_tags"] = og

        return tech

# ─── Module 4: Digital Identity / Username Enum ───────────────────────────────

class IdentityIntel:
    """Username enumeration across platforms."""

    PLATFORMS = {
        "GitHub": "https://github.com/{username}",
        "GitLab": "https://gitlab.com/{username}",
        "Twitter/X": "https://twitter.com/{username}",
        "Instagram": "https://www.instagram.com/{username}/",
        "Reddit": "https://www.reddit.com/user/{username}",
        "LinkedIn": "https://www.linkedin.com/in/{username}",
        "TikTok": "https://www.tiktok.com/@{username}",
        "YouTube": "https://www.youtube.com/@{username}",
        "Pinterest": "https://www.pinterest.com/{username}/",
        "Twitch": "https://www.twitch.tv/{username}",
        "Steam": "https://steamcommunity.com/id/{username}",
        "HackerNews": "https://news.ycombinator.com/user?id={username}",
        "Medium": "https://medium.com/@{username}",
        "Dev.to": "https://dev.to/{username}",
        "Keybase": "https://keybase.io/{username}",
        "Pastebin": "https://pastebin.com/u/{username}",
        "DockerHub": "https://hub.docker.com/u/{username}",
        "npm": "https://www.npmjs.com/~{username}",
        "PyPI": "https://pypi.org/user/{username}",
        "Replit": "https://replit.com/@{username}",
        "HackTheBox": "https://app.hackthebox.com/profile/{username}",
        "TryHackMe": "https://tryhackme.com/p/{username}",
        "Bugcrowd": "https://bugcrowd.com/{username}",
        "HackerOne": "https://hackerone.com/{username}",
    }

    @classmethod
    async def enumerate(cls, session: aiohttp.ClientSession, username: str) -> list[dict]:
        results = []

        async def check(name, url_template):
            url = url_template.format(username=username)
            try:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False, allow_redirects=True
                ) as r:
                    found = r.status == 200
                    results.append({
                        "platform": name,
                        "url": url,
                        "found": found,
                        "status": r.status,
                    })
            except Exception:
                results.append({"platform": name, "url": url, "found": False, "status": None})

        tasks = [check(name, tmpl) for name, tmpl in cls.PLATFORMS.items()]
        await asyncio.gather(*tasks)
        return sorted(results, key=lambda x: (not x["found"], x["platform"]))

    @staticmethod
    def generate_email_permutations(first: str, last: str, domain: str) -> list[str]:
        f, l = first.lower(), last.lower()
        return [
            f"{f}.{l}@{domain}",
            f"{f}{l}@{domain}",
            f"{f[0]}{l}@{domain}",
            f"{f}.{l[0]}@{domain}",
            f"{l}.{f}@{domain}",
            f"{l}{f}@{domain}",
            f"{f}@{domain}",
            f"{l}@{domain}",
            f"{f[0]}.{l}@{domain}",
        ]

    @staticmethod
    async def hibp_check(session: aiohttp.ClientSession, email: str, api_key: str = "") -> dict:
        headers = {"hibp-api-key": api_key, "User-Agent": "GhostBuster-OSINT"}
        encoded = email.replace("@", "%40")
        data = await fetch(session,
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{encoded}?truncateResponse=false",
            headers=headers
        )
        if isinstance(data, list):
            return {
                "email": email,
                "breached": True,
                "breach_count": len(data),
                "breaches": [{"name": b.get("Name"), "date": b.get("BreachDate"),
                              "data_classes": b.get("DataClasses", [])} for b in data],
            }
        return {"email": email, "breached": False}

# ─── Module 5: EXIF / Image Intel ────────────────────────────────────────────

class ImageIntel:
    @staticmethod
    def extract_exif(filepath: str) -> dict:
        if not EXIF_AVAILABLE:
            return {"error": "exifread not installed"}
        try:
            with open(filepath, "rb") as f:
                tags = exifread.process_file(f, details=False)
            result = {}
            for key, val in tags.items():
                result[key] = str(val)

            gps = {}
            def dms_to_decimal(dms, ref):
                parts = str(dms).strip("[]").split(", ")
                deg = float(parts[0]) if parts else 0
                mn = float(parts[1]) if len(parts) > 1 else 0
                sec = float(parts[2]) if len(parts) > 2 else 0
                decimal = deg + mn / 60 + sec / 3600
                if ref in ("S", "W"):
                    decimal = -decimal
                return round(decimal, 6)

            lat = tags.get("GPS GPSLatitude")
            lat_ref = tags.get("GPS GPSLatitudeRef")
            lon = tags.get("GPS GPSLongitude")
            lon_ref = tags.get("GPS GPSLongitudeRef")
            if lat and lon:
                gps["latitude"] = dms_to_decimal(lat, str(lat_ref))
                gps["longitude"] = dms_to_decimal(lon, str(lon_ref))
                gps["maps_link"] = (f"https://maps.google.com/?q="
                                    f"{gps['latitude']},{gps['longitude']}")
            result["_gps"] = gps
            result["_device"] = {
                "make": str(tags.get("Image Make", "")),
                "model": str(tags.get("Image Model", "")),
                "software": str(tags.get("Image Software", "")),
                "datetime": str(tags.get("Image DateTime", "")),
            }
            return result
        except Exception as e:
            return {"error": str(e)}

# ─── Graph Visualization ──────────────────────────────────────────────────────

class GraphBuilder:
    def __init__(self):
        self.G = nx.Graph() if GRAPH_AVAILABLE else None

    def add_node(self, node_id: str, **attrs):
        if self.G:
            self.G.add_node(node_id, **attrs)

    def add_edge(self, src: str, dst: str, label: str = ""):
        if self.G:
            self.G.add_edge(src, dst, label=label)

    def render(self, output: str = "ghostbuster_graph.png"):
        if not GRAPH_AVAILABLE:
            log.warning("networkx/matplotlib not installed — skipping graph")
            return
        plt.figure(figsize=(16, 12))
        pos = nx.spring_layout(self.G, k=2, seed=42)
        nx.draw_networkx(self.G, pos, with_labels=True, node_size=1200,
                         node_color="#1a1a2e", font_color="white",
                         edge_color="#e94560", font_size=8)
        edge_labels = nx.get_edge_attributes(self.G, "label")
        nx.draw_networkx_edge_labels(self.G, pos, edge_labels=edge_labels, font_size=7)
        plt.tight_layout()
        plt.savefig(output, dpi=150, bbox_inches="tight")
        log.info(f"Graph saved: {output}")

# ─── Output Formatters ────────────────────────────────────────────────────────

class Reporter:
    @staticmethod
    def to_json(data: dict, path: str):
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        log.info(f"JSON report: {path}")

    @staticmethod
    def to_xml(data: dict, path: str):
        def dict_to_xml(d, parent):
            for k, v in d.items():
                tag = re.sub(r'[^a-zA-Z0-9_]', '_', str(k))
                child = ET.SubElement(parent, tag)
                if isinstance(v, dict):
                    dict_to_xml(v, child)
                elif isinstance(v, list):
                    for item in v:
                        sub = ET.SubElement(child, "item")
                        if isinstance(item, dict):
                            dict_to_xml(item, sub)
                        else:
                            sub.text = str(item)
                else:
                    child.text = str(v) if v is not None else ""

        root = ET.Element("ghostbuster_report")
        dict_to_xml(data, root)
        tree = ET.ElementTree(root)
        ET.indent(tree, space="  ")
        tree.write(path, encoding="unicode", xml_declaration=True)
        log.info(f"XML report: {path}")

# ─── Core Investigation Engine ────────────────────────────────────────────────

class GhostBusterEngine:
    def __init__(self, config: dict):
        self.config = config
        self.graph = GraphBuilder()

    async def investigate_ip(self, session, ip: str) -> dict:
        log.info(f"[IP] Investigating {ip}")
        geo, proxy, rdns = await asyncio.gather(
            IPIntel.geolocate(session, ip),
            IPIntel.check_proxy_vpn(session, ip),
            IPIntel.reverse_dns(ip),
        )
        shodan = {}
        if self.config.get("shodan_key"):
            shodan = await IPIntel.shodan_lookup(session, ip, self.config["shodan_key"])

        self.graph.add_node(ip, type="ip", city=geo.get("city"), country=geo.get("country"))
        for h in rdns:
            self.graph.add_node(h, type="hostname")
            self.graph.add_edge(ip, h, label="reverse_dns")

        return {"ip": ip, "geo": geo, "proxy_vpn": proxy, "reverse_dns": rdns, "shodan": shodan}

    async def investigate_domain(self, session, domain: str) -> dict:
        log.info(f"[DOMAIN] Investigating {domain}")
        dns, whois, subdomains, wayback = await asyncio.gather(
            DomainIntel.dns_lookup(domain),
            DomainIntel.whois_lookup(session, domain),
            DomainIntel.cert_transparency(session, domain),
            DomainIntel.wayback_lookup(session, domain),
        )
        tech = await DomainIntel.tech_fingerprint(session, f"https://{domain}")

        self.graph.add_node(domain, type="domain")
        for sub in subdomains:
            if sub != domain:
                self.graph.add_node(sub, type="subdomain")
                self.graph.add_edge(domain, sub, label="subdomain")

        return {
            "domain": domain,
            "dns": dns,
            "whois": whois,
            "subdomains": subdomains,
            "wayback_snapshots": wayback,
            "tech": tech,
        }

    async def investigate_url(self, session, url: str) -> dict:
        log.info(f"[URL] Investigating {url}")
        expanded = await DomainIntel.expand_url(session, url)
        parsed = urlparse(expanded["final"])
        domain_data = {}
        if parsed.hostname:
            domain_data = await self.investigate_domain(session, parsed.hostname)
        return {"url_expansion": expanded, "domain_intel": domain_data}

    async def investigate_username(self, session, username: str) -> dict:
        log.info(f"[USERNAME] Enumerating {username}")
        results = await IdentityIntel.enumerate(session, username)
        found = [r for r in results if r["found"]]
        self.graph.add_node(username, type="username")
        for r in found:
            self.graph.add_node(r["platform"], type="platform")
            self.graph.add_edge(username, r["platform"], label="found")
        return {"username": username, "found_count": len(found), "platforms": results}

    async def investigate_email(self, session, email: str) -> dict:
        log.info(f"[EMAIL] Investigating {email}")
        hibp = {}
        if self.config.get("hibp_key"):
            hibp = await IdentityIntel.hibp_check(session, email, self.config["hibp_key"])
        elif self.config.get("check_breaches", False):
            log.warning("HIBP requires API key — skipping breach check")
        return {"email": email, "hibp": hibp}

    async def investigate_phone(self, phone: str) -> dict:
        log.info(f"[PHONE] Analyzing {phone}")
        return PhoneIntel.analyze(phone)

    async def run(self, targets: list[dict]) -> dict:
        connector = aiohttp.TCPConnector(limit=50, ssl=False)
        proxy = self.config.get("proxy")
        async with aiohttp.ClientSession(
            headers=make_headers(),
            connector=connector,
            trust_env=True
        ) as session:
            findings = {
                "meta": {
                    "generated": datetime.now().isoformat(),
                    "target_count": len(targets),
                    "tool": "GhostBuster OSINT Framework",
                },
                "results": [],
            }

            tasks = []
            for t in targets:
                ttype = t.get("type")
                value = t.get("value")
                if ttype == "ip":
                    tasks.append(self.investigate_ip(session, value))
                elif ttype == "domain":
                    tasks.append(self.investigate_domain(session, value))
                elif ttype == "url":
                    tasks.append(self.investigate_url(session, value))
                elif ttype == "username":
                    tasks.append(self.investigate_username(session, value))
                elif ttype == "email":
                    tasks.append(self.investigate_email(session, value))
                elif ttype == "phone":
                    tasks.append(self.investigate_phone(value))
                elif ttype == "image":
                    tasks.append(asyncio.coroutine(lambda v=value: {"exif": ImageIntel.extract_exif(v)})())
                else:
                    log.warning(f"Unknown target type: {ttype}")

            results = await asyncio.gather(*tasks, return_exceptions=True)
            for t, r in zip(targets, results):
                if isinstance(r, Exception):
                    findings["results"].append({"target": t, "error": str(r)})
                else:
                    findings["results"].append({"target": t, "data": r})

        return findings

# ─── Config Loader ────────────────────────────────────────────────────────────

def load_config(path: str = "config.yaml") -> dict:
    defaults = {
        "shodan_key": "",
        "hibp_key": "",
        "proxy": None,
        "output_format": "json",
        "graph": False,
        "log_level": "INFO",
    }
    if Path(path).exists():
        with open(path) as f:
            user = yaml.safe_load(f) or {}
        defaults.update(user)
    return defaults

# ─── Bulk Input Parsers ────────────────────────────────────────────────────────

def parse_bulk_file(filepath: str) -> list[dict]:
    targets = []
    path = Path(filepath)
    if not path.exists():
        log.error(f"File not found: {filepath}")
        return targets

    if filepath.endswith(".json"):
        with open(filepath) as f:
            data = json.load(f)
        return data if isinstance(data, list) else [data]

    if filepath.endswith(".csv"):
        with open(filepath) as f:
            reader = csv.DictReader(f)
            for row in reader:
                targets.append({"type": row.get("type", "domain"), "value": row.get("value", "")})
        return targets

    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', line):
                targets.append({"type": "ip", "value": line})
            elif re.match(r'^https?://', line):
                targets.append({"type": "url", "value": line})
            elif re.match(r'^[\w.+-]+@[\w-]+\.[a-z]{2,}$', line, re.IGNORECASE):
                targets.append({"type": "email", "value": line})
            elif re.match(r'^\+?\d[\d\s\-().]{7,}$', line):
                targets.append({"type": "phone", "value": line})
            else:
                targets.append({"type": "domain", "value": line})
    return targets

# ─── CLI ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ghostbuster",
        description="GhostBuster OSINT Framework — authorized penetration testing tool",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # Single target
    inv = sub.add_parser("investigate", aliases=["inv"], help="Investigate a single target")
    inv.add_argument("type", choices=["ip","domain","url","username","email","phone","image"])
    inv.add_argument("value", help="Target value")

    # Bulk
    bulk = sub.add_parser("bulk", help="Bulk processing from file")
    bulk.add_argument("file", help="CSV/JSON/TXT file")

    # Common options
    for sp in [inv, bulk]:
        sp.add_argument("-c", "--config", default="config.yaml")
        sp.add_argument("-o", "--output", default="ghostbuster_report")
        sp.add_argument("-f", "--format", choices=["json","xml","both"], default="json")
        sp.add_argument("--graph", action="store_true")
        sp.add_argument("--log-level", default="INFO")

    return p

async def main_async(args):
    config = load_config(args.config)
    config["graph"] = args.graph
    setup_logging(level=args.log_level)

    if args.command in ("investigate", "inv"):
        targets = [{"type": args.type, "value": args.value}]
    else:
        targets = parse_bulk_file(args.file)

    if not targets:
        log.error("No targets to investigate")
        sys.exit(1)

    log.info(f"GhostBuster starting — {len(targets)} target(s)")
    engine = GhostBusterEngine(config)
    findings = await engine.run(targets)

    fmt = args.format
    base = args.output
    if fmt in ("json", "both"):
        Reporter.to_json(findings, f"{base}.json")
    if fmt in ("xml", "both"):
        Reporter.to_xml(findings, f"{base}.xml")

    if args.graph:
        engine.graph.render(f"{base}_graph.png")

    # Print summary
    print("\n" + "="*60)
    print("  GhostBuster OSINT — Results Summary")
    print("="*60)
    for item in findings["results"]:
        t = item["target"]
        print(f"\n[{t['type'].upper()}] {t['value']}")
        if "error" in item:
            print(f"  ERROR: {item['error']}")
        else:
            data = item.get("data", {})
            if t["type"] == "ip":
                geo = data.get("geo", {})
                print(f"  Location : {geo.get('city')}, {geo.get('country')}")
                print(f"  Org/ASN  : {geo.get('org')}")
                pv = data.get("proxy_vpn", {})
                if pv.get("vpn") or pv.get("proxy"):
                    print(f"  VPN/Proxy: YES — {pv.get('type')} / {pv.get('provider')}")
                rdns = data.get("reverse_dns", [])
                if rdns:
                    print(f"  RDNS     : {', '.join(rdns)}")
                sh = data.get("shodan", {})
                if sh.get("ports"):
                    print(f"  Ports    : {sh['ports']}")
                if sh.get("vulns"):
                    print(f"  CVEs     : {sh['vulns']}")

            elif t["type"] == "domain":
                subs = data.get("subdomains", [])
                print(f"  Subdomains: {len(subs)} found")
                for s in subs[:10]:
                    print(f"    - {s}")
                tech = data.get("tech", {})
                if tech.get("server"):
                    print(f"  Server   : {tech['server']}")
                if tech.get("frameworks"):
                    print(f"  Tech     : {', '.join(tech['frameworks'])}")

            elif t["type"] == "username":
                found = [r for r in data.get("platforms", []) if r["found"]]
                print(f"  Found on {len(found)} platforms:")
                for r in found:
                    print(f"    [{r['platform']}] {r['url']}")

            elif t["type"] == "phone":
                print(f"  E.164    : {data.get('e164')}")
                print(f"  Carrier  : {data.get('carrier')}")
                print(f"  Region   : {data.get('region')}")
                print(f"  Type     : {data.get('line_type')}")

            elif t["type"] == "email":
                hibp = data.get("hibp", {})
                if hibp.get("breached"):
                    print(f"  BREACHED : YES — {hibp.get('breach_count')} breaches")
                    for b in hibp.get("breaches", [])[:5]:
                        print(f"    - {b['name']} ({b['date']})")
                else:
                    print(f"  Breached : No breaches found")

    print("\n" + "="*60)
    print(f"Full report saved to: {base}.json")

_G = "\033[38;5;46m"      # neon green
_O = "\033[38;5;208m"     # neon orange
_W = "\033[38;5;255m"     # bright white
_D = "\033[38;5;240m"     # dim
_B = "\033[1m"            # bold
_R = "\033[0m"            # reset

BANNER = f"""
{_G}   ▄████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓{_O} ▄▄▄▄    █    ██   ██████ ▄▄▄█████▓▓█████  ██▀███  {_R}
{_G}  ██▒ ▀█▒▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒{_O}▓█████▄  ██  ▓██▒▒██    ▒ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒{_R}
{_G} ▒██░▄▄▄░▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░{_O}▒██▒ ▄██▓██  ▒██░░ ▓██▄   ▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒{_R}
{_G} ░▓█  ██▓░▓█ ░██ ▒██   ██░  ▒   ██▒░ ▓██▓ ░ {_O}▒██░█▀  ▓▓█  ░██░  ▒   ██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  {_R}
{_G} ░▒▓███▀▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░ {_O}░▓█  ▀█▓▒▒█████▓ ▒██████▒▒  ▒██▒ ░ ░▒████▒░██▓ ▒██▒{_R}
{_G}  ░▒   ▒  ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░   {_O}░▒▓███▀▒░▒▓▒ ▒ ▒ ▒ ▒▓▒ ▒ ░  ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░{_R}
{_G}   ░   ░  ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░    {_O}▒░▒   ░ ░░▒░ ░ ░ ░ ░▒  ░ ░    ░     ░ ░  ░  ░▒ ░ ▒░{_R}
{_G} ░ ░   ░  ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░      {_O} ░    ░  ░░░ ░ ░ ░  ░  ░    ░         ░     ░░   ░ {_R}
{_G}       ░  ░  ░  ░    ░ ░        ░           {_O} ░         ░           ░              ░  ░   ░     {_R}

{_D}           ┌─────────────────────────────────────────────────────────────────┐{_R}
{_D}           │{_R}  {_O}{_B}👻 GhostBuster{_R}  {_D}•{_R}  {_W}OSINT Reconnaissance Framework{_R}  {_D}•{_R}  {_G}v1.0.0{_R}  {_D}│{_R}
{_D}           │{_R}  {_W}Developed by{_R} {_O}{_B}Yaman.RedTeam{_R}  {_D}•{_R}  {_G}Authorized Testing Only{_R}         {_D}│{_R}
{_D}           │{_R}  {_D}➜{_R} {_W}github.com/Yaman-RedTeam/ghostbuster{_R}                            {_D}│{_R}
{_D}           └─────────────────────────────────────────────────────────────────┘{_R}
"""

def print_banner():
    try:
        print(BANNER)
    except UnicodeEncodeError:
        pass

def main():
    print_banner()
    parser = build_parser()
    args = parser.parse_args()
    asyncio.run(main_async(args))

if __name__ == "__main__":
    main()
