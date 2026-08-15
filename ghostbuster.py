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

# ISO2 → English country name (small helper, no external dep)
_ISO2_TO_NAME = {
    "US":"United States","IN":"India","GB":"United Kingdom","CA":"Canada",
    "AU":"Australia","DE":"Germany","FR":"France","IT":"Italy","ES":"Spain",
    "JP":"Japan","CN":"China","KR":"South Korea","BR":"Brazil","MX":"Mexico",
    "RU":"Russia","ZA":"South Africa","NG":"Nigeria","AE":"UAE","SA":"Saudi Arabia",
    "PK":"Pakistan","BD":"Bangladesh","LK":"Sri Lanka","NP":"Nepal","MM":"Myanmar",
    "TH":"Thailand","VN":"Vietnam","ID":"Indonesia","PH":"Philippines","MY":"Malaysia",
    "SG":"Singapore","HK":"Hong Kong","TW":"Taiwan","NZ":"New Zealand","NL":"Netherlands",
    "BE":"Belgium","CH":"Switzerland","SE":"Sweden","NO":"Norway","DK":"Denmark",
    "FI":"Finland","IE":"Ireland","PT":"Portugal","GR":"Greece","PL":"Poland",
    "CZ":"Czechia","AT":"Austria","HU":"Hungary","RO":"Romania","UA":"Ukraine",
    "TR":"Turkey","IL":"Israel","EG":"Egypt","MA":"Morocco","DZ":"Algeria",
    "TN":"Tunisia","KE":"Kenya","ET":"Ethiopia","GH":"Ghana","AR":"Argentina",
    "CL":"Chile","CO":"Colombia","PE":"Peru","VE":"Venezuela","IR":"Iran","AF":"Afghanistan",
}
def _country_english_name(iso2: str) -> str:
    return _ISO2_TO_NAME.get((iso2 or "").upper(), iso2 or "Unknown")

# ── India telecom circle lookup (originally-assigned circle by first 4 digits) ──
# Based on DoT/TRAI Numbering Plan. Post-MNP the current operator may differ,
# but the original circle (state/region) remains the same for that prefix.
# Format:  "9118" → ("Uttar Pradesh East", "Uninor/Telewings")
INDIA_CIRCLES = {
    # 70xx series
    "7000":("Bihar","BSNL"), "7001":("West Bengal","Airtel"), "7002":("Assam","Airtel"),
    "7005":("Bihar","Airtel"), "7008":("Odisha","BSNL"), "7011":("Delhi","Airtel"),
    "7013":("Andhra Pradesh","Airtel"), "7018":("Himachal Pradesh","Airtel"),
    "7019":("Karnataka","Airtel"), "7020":("Maharashtra","Idea"), "7021":("Mumbai","Vodafone"),
    "7022":("Karnataka","Vodafone"), "7023":("Rajasthan","Vodafone"),
    "7028":("Maharashtra","Vodafone"), "7030":("Maharashtra","Airtel"),
    "7033":("Bihar","Reliance Jio"), "7038":("Maharashtra","Idea"),
    "7042":("Delhi","Vodafone"), "7044":("Kolkata","Airtel"), "7045":("Mumbai","Reliance"),
    "7060":("UP West","Airtel"), "7065":("Rajasthan","Airtel"), "7070":("Bihar","Airtel"),
    "7071":("Rajasthan","Airtel"), "7073":("Rajasthan","Airtel"),
    "7075":("Andhra Pradesh","Airtel"), "7080":("UP East","Airtel"),
    "7081":("UP West","Airtel"), "7082":("Haryana","Airtel"),
    "7083":("Madhya Pradesh","Airtel"), "7084":("Punjab","Airtel"),
    "7085":("North East","Airtel"), "7086":("Assam","Airtel"),
    "7087":("Punjab","Airtel"), "7088":("UP West","Airtel"), "7091":("Kolkata","Vodafone"),
    "7092":("Chennai","Vodafone"), "7093":("Andhra Pradesh","Idea"),
    "7094":("Tamil Nadu","Idea"), "7095":("Andhra Pradesh","Idea"),
    "7097":("Karnataka","Idea"),
    # 80xx / 81xx / 82xx
    "8000":("Rajasthan","Reliance"), "8001":("West Bengal","Reliance Jio"),
    "8003":("Rajasthan","Airtel"), "8004":("UP East","Airtel"), "8005":("UP West","Airtel"),
    "8006":("UP West","Vodafone"), "8007":("Maharashtra","Idea"), "8008":("Andhra Pradesh","Idea"),
    "8009":("UP East","Vodafone"), "8010":("Delhi","Vodafone"),
    "8011":("Assam","Vodafone"), "8013":("West Bengal","Vodafone"),
    "8017":("Kolkata","Vodafone"), "8018":("Odisha","Airtel"),
    "8019":("Andhra Pradesh","Airtel"), "8095":("Karnataka","Airtel"),
    "8096":("Maharashtra","Vodafone"), "8097":("Mumbai","Vodafone"),
    "8100":("West Bengal","Airtel"), "8106":("Andhra Pradesh","Airtel"),
    "8125":("Andhra Pradesh","BSNL"), "8126":("UP West","BSNL"),
    "8130":("Delhi","Airtel"), "8146":("Punjab","Airtel"),
    "8147":("Karnataka","Airtel"), "8148":("Tamil Nadu","Airtel"),
    "8149":("Maharashtra","Idea"), "8150":("Karnataka","Airtel"),
    "8171":("UP West","Airtel"), "8178":("Delhi","Airtel"), "8179":("Andhra Pradesh","Airtel"),
    "8181":("UP East","BSNL"), "8191":("Himachal Pradesh","Airtel"),
    "8195":("Punjab","Idea"), "8197":("Karnataka","Airtel"),
    "8235":("Bihar","Idea"), "8240":("Kolkata","Reliance"),
    "8250":("West Bengal","BSNL"), "8264":("Punjab","Reliance"),
    "8285":("Delhi","Reliance"), "8287":("Delhi","Idea"), "8288":("Delhi","Airtel"),
    # 90xx / 91xx / 92xx / 93xx / 94xx / 95xx / 96xx / 97xx / 98xx / 99xx
    "9000":("Andhra Pradesh","Airtel"), "9006":("Bihar","Airtel"),
    "9007":("Kolkata","Airtel"), "9008":("Karnataka","Airtel"),
    "9010":("Andhra Pradesh","Reliance"), "9013":("Delhi","Airtel"),
    "9015":("Delhi","Reliance"), "9016":("Gujarat","Reliance"),
    "9027":("UP West","Reliance"), "9034":("Haryana","Reliance"),
    "9036":("Karnataka","Reliance"), "9038":("Kolkata","Reliance"),
    "9040":("Odisha","Reliance"), "9044":("UP East","Reliance"),
    "9050":("Haryana","Vodafone"), "9058":("UP West","Airtel"),
    "9060":("Tamil Nadu","Reliance"), "9066":("Karnataka","Reliance"),
    "9068":("UP West","Reliance"), "9069":("UP East","Reliance"),
    "9071":("Karnataka","Idea"), "9074":("West Bengal","Idea"),
    "9078":("Odisha","Idea"), "9079":("Rajasthan","Airtel"),
    "9080":("Chennai","Airtel"), "9082":("Mumbai","Vodafone"),
    "9083":("Kolkata","Vodafone"), "9088":("Kolkata","Uninor"),
    "9090":("Odisha","Airtel"), "9091":("Karnataka","Airtel"),
    "9092":("Tamil Nadu","Airtel"), "9093":("Chennai","Airtel"),
    "9094":("Chennai","Airtel"), "9095":("Kerala","Airtel"),
    "9096":("Maharashtra","Airtel"), "9097":("West Bengal","Airtel"),
    "9098":("Madhya Pradesh","Airtel"), "9099":("Gujarat","Airtel"),
    "9100":("Andhra Pradesh","BSNL"), "9110":("Karnataka","Airtel"),
    "9111":("Madhya Pradesh","Reliance"), "9112":("Maharashtra","Reliance"),
    "9113":("Karnataka","Reliance"), "9114":("Odisha","Reliance"),
    "9115":("Punjab","Reliance"), "9116":("Rajasthan","Reliance"),
    "9117":("UP West","Reliance"),
    "9118":("UP East","Uninor/Telewings"),
    "9119":("UP West","Reliance Jio"), "9120":("UP East","BSNL"),
    "9122":("Bihar","BSNL"), "9123":("Kolkata","Uninor"),
    "9124":("UP East","Aircel"), "9125":("UP East","Aircel"),
    "9126":("West Bengal","Uninor"), "9127":("Bihar","Uninor"),
    "9128":("Bihar","Uninor"), "9129":("UP East","Aircel"),
    "9130":("Maharashtra","Idea"), "9131":("Madhya Pradesh","Vodafone"),
    "9140":("UP East","Reliance"), "9142":("Bihar","Reliance"),
    "9143":("Kolkata","Reliance"), "9144":("Chennai","Reliance"),
    "9145":("Maharashtra","Reliance"), "9146":("Punjab","Uninor"),
    "9147":("West Bengal","Uninor"), "9148":("Karnataka","Uninor"),
    "9149":("Gujarat","Reliance"), "9150":("Chennai","Reliance"),
    "9151":("UP East","Vodafone"), "9152":("Mumbai","Vodafone"),
    "9153":("Kolkata","Vodafone"), "9154":("Andhra Pradesh","Vodafone"),
    "9155":("Bihar","Vodafone"), "9156":("Maharashtra","Vodafone"),
    "9157":("Gujarat","Vodafone"), "9158":("Maharashtra","Vodafone"),
    "9159":("Tamil Nadu","Vodafone"), "9160":("Andhra Pradesh","Aircel"),
    "9162":("Bihar","Airtel"), "9163":("Kolkata","Airtel"),
    "9164":("Karnataka","Airtel"), "9165":("UP East","Airtel"),
    "9166":("Rajasthan","Airtel"), "9167":("Mumbai","Vodafone"),
    "9168":("Maharashtra","Idea"), "9169":("Haryana","BSNL"),
    "9170":("Bihar","Airtel"), "9171":("Madhya Pradesh","Airtel"),
    "9172":("Karnataka","Airtel"), "9173":("Gujarat","Idea"),
    "9174":("Madhya Pradesh","Idea"), "9175":("Maharashtra","Idea"),
    "9176":("Chennai","Aircel"), "9177":("Andhra Pradesh","Airtel"),
    "9178":("Odisha","Airtel"), "9179":("Madhya Pradesh","Airtel"),
    "9180":("Karnataka","BSNL"), "9181":("Andhra Pradesh","Airtel"),
    "9182":("Andhra Pradesh","Airtel"), "9183":("Karnataka","BSNL"),
    "9184":("Chennai","BSNL"), "9186":("Bihar","BSNL"),
    "9187":("Assam","BSNL"), "9188":("Kerala","BSNL"),
    "9189":("North East","Airtel"), "9190":("UP East","BSNL"),
    "9191":("UP East","Vodafone"), "9192":("Rajasthan","BSNL"),
    "9193":("West Bengal","BSNL"), "9194":("Madhya Pradesh","BSNL"),
    "9195":("Gujarat","BSNL"), "9196":("Karnataka","BSNL"),
    "9198":("Punjab","BSNL"), "9199":("Bihar","BSNL"),
    "9200":("Madhya Pradesh","Airtel"), "9210":("Delhi","Reliance"),
    "9211":("Delhi","Idea"), "9212":("Delhi","Airtel"),
    "9213":("Delhi","Airtel"), "9214":("Rajasthan","Airtel"),
    "9215":("Haryana","Reliance"), "9216":("Punjab","Vodafone"),
    "9217":("Haryana","Vodafone"), "9218":("Himachal Pradesh","Vodafone"),
    "9219":("UP West","Vodafone"), "9220":("Mumbai","Reliance"),
    "9221":("Mumbai","Reliance"), "9223":("Mumbai","Reliance"),
    "9224":("Maharashtra","Reliance"), "9225":("Maharashtra","Reliance"),
    "9226":("Maharashtra","Reliance"), "9227":("Gujarat","Reliance"),
    "9228":("UP West","Reliance"), "9229":("Madhya Pradesh","Reliance"),
    "9230":("Kolkata","Airtel"), "9231":("Kolkata","Airtel"),
    "9232":("Kolkata","Reliance"), "9233":("West Bengal","Reliance"),
    "9234":("Bihar","Reliance"), "9235":("UP East","Reliance"),
    "9236":("UP West","Reliance"), "9237":("Odisha","Reliance"),
    "9238":("Odisha","Reliance"), "9239":("Bihar","Reliance"),
    "9240":("Karnataka","Reliance"), "9241":("Karnataka","Reliance"),
    "9243":("Karnataka","Reliance"), "9244":("Kerala","Reliance"),
    "9245":("Chennai","Reliance"), "9246":("Andhra Pradesh","Reliance"),
    "9247":("Andhra Pradesh","Reliance"), "9248":("Andhra Pradesh","Reliance"),
    "9250":("Delhi","Reliance"), "9251":("Rajasthan","Reliance"),
    "9252":("Rajasthan","Reliance"), "9253":("Haryana","Reliance"),
    "9254":("Haryana","Reliance"), "9255":("Punjab","Reliance"),
    "9256":("Punjab","Reliance"), "9257":("Rajasthan","Reliance"),
    "9258":("UP West","Reliance"), "9259":("UP West","Reliance"),
    "9260":("Maharashtra","Reliance"), "9261":("Rajasthan","Reliance"),
    "9262":("Bihar","Reliance"), "9263":("Delhi","Idea"),
    "9264":("Bihar","Aircel"), "9265":("Gujarat","Reliance"),
    "9266":("Delhi","Idea"), "9267":("Delhi","Reliance"),
    "9268":("Delhi","Reliance"), "9269":("Rajasthan","Reliance"),
    "9270":("Maharashtra","Reliance"), "9271":("Maharashtra","Reliance"),
    "9272":("Maharashtra","Reliance"), "9273":("Maharashtra","Reliance"),
    "9274":("Gujarat","Reliance"), "9275":("Maharashtra","Reliance"),
    "9276":("Kerala","Reliance"), "9277":("Andhra Pradesh","Reliance"),
    "9278":("Delhi","Reliance"), "9279":("UP East","Reliance"),
    "9280":("Tamil Nadu","Reliance"), "9281":("Andhra Pradesh","Reliance"),
    "9282":("Chennai","Reliance"), "9283":("Chennai","Reliance"),
    "9284":("Maharashtra","Reliance"), "9285":("Delhi","Reliance"),
    "9286":("Karnataka","Reliance"), "9287":("Kolkata","Reliance"),
    "9289":("Delhi","Reliance"), "9290":("Andhra Pradesh","Reliance"),
    "9291":("Andhra Pradesh","Reliance"), "9292":("Andhra Pradesh","Reliance"),
    "9293":("Andhra Pradesh","Reliance"), "9294":("Andhra Pradesh","Reliance"),
    "9295":("UP East","Reliance"), "9296":("Maharashtra","Reliance"),
    "9297":("Karnataka","Reliance"), "9298":("Andhra Pradesh","Reliance"),
    "9299":("Andhra Pradesh","Reliance"),
    "9300":("Madhya Pradesh","Reliance"),
    "9310":("Delhi","Vodafone"), "9311":("Delhi","Vodafone"),
    "9312":("Delhi","Airtel"), "9313":("Delhi","Vodafone"),
    "9314":("Rajasthan","Vodafone"), "9315":("Delhi","Reliance"),
    "9316":("Gujarat","Vodafone"), "9317":("Haryana","Idea"),
    "9318":("Delhi","Reliance Jio"), "9319":("Delhi","Vodafone"),
    "9320":("Mumbai","Vodafone"), "9321":("Mumbai","Vodafone"),
    "9322":("Mumbai","Vodafone"), "9323":("Mumbai","Vodafone"),
    "9324":("Mumbai","Vodafone"), "9325":("Maharashtra","Vodafone"),
    "9326":("Maharashtra","Vodafone"), "9327":("Gujarat","Vodafone"),
    "9328":("Gujarat","Vodafone"), "9329":("Madhya Pradesh","Vodafone"),
    "9330":("Kolkata","Vodafone"), "9331":("Kolkata","Vodafone"),
    "9332":("West Bengal","Vodafone"), "9333":("Kolkata","Vodafone"),
    "9334":("Bihar","Airtel"), "9335":("UP East","Airtel"),
    "9336":("UP East","Airtel"), "9337":("Odisha","Vodafone"),
    "9338":("Odisha","Airtel"), "9339":("Kolkata","Vodafone"),
    "9340":("Madhya Pradesh","Vodafone"), "9341":("Karnataka","Airtel"),
    "9342":("Karnataka","Airtel"), "9343":("Karnataka","Airtel"),
    "9344":("Chennai","Airtel"), "9345":("Chennai","Airtel"),
    "9346":("Andhra Pradesh","Airtel"), "9347":("Andhra Pradesh","Airtel"),
    "9348":("Odisha","Airtel"), "9349":("Kerala","BSNL"),
    "9350":("Delhi","Vodafone"), "9351":("Rajasthan","Airtel"),
    "9352":("Rajasthan","Airtel"), "9353":("Karnataka","Airtel"),
    "9354":("Delhi","Airtel"), "9355":("Delhi","Airtel"),
    "9356":("Maharashtra","Idea"), "9357":("Punjab","Airtel"),
    "9358":("Haryana","Airtel"), "9359":("Maharashtra","Idea"),
    "9360":("Tamil Nadu","Airtel"), "9361":("Tamil Nadu","Airtel"),
    "9362":("Tamil Nadu","Airtel"), "9363":("Chennai","Airtel"),
    "9364":("Tamil Nadu","BSNL"), "9365":("Assam","Airtel"),
    "9366":("Chennai","Vodafone"), "9367":("Tamil Nadu","Airtel"),
    "9368":("UP West","Airtel"), "9369":("UP East","Airtel"),
    "9370":("Maharashtra","BSNL"), "9371":("Maharashtra","BSNL"),
    "9372":("Mumbai","Vodafone"), "9373":("Maharashtra","BSNL"),
    "9374":("Gujarat","Airtel"), "9375":("Gujarat","BSNL"),
    "9376":("Gujarat","BSNL"), "9377":("Gujarat","Airtel"),
    "9378":("Gujarat","Airtel"), "9379":("Karnataka","BSNL"),
    "9380":("Chennai","Airtel"), "9381":("Chennai","BSNL"),
    "9382":("Chennai","BSNL"), "9383":("Kerala","BSNL"),
    "9384":("Tamil Nadu","BSNL"), "9385":("Tamil Nadu","BSNL"),
    "9386":("Bihar","BSNL"), "9387":("Kerala","BSNL"),
    "9388":("Kerala","BSNL"), "9389":("UP West","BSNL"),
    "9390":("Andhra Pradesh","Airtel"), "9391":("Andhra Pradesh","Airtel"),
    "9392":("Andhra Pradesh","BSNL"), "9393":("Andhra Pradesh","BSNL"),
    "9394":("Andhra Pradesh","BSNL"), "9395":("Assam","BSNL"),
    "9396":("Andhra Pradesh","BSNL"), "9397":("Andhra Pradesh","BSNL"),
    "9398":("Andhra Pradesh","BSNL"), "9399":("Madhya Pradesh","BSNL"),
    # Sample 94-99 series (heavy set of common ones)
    "9400":("Kerala","BSNL"), "9401":("North East","BSNL"),
    "9403":("Maharashtra","BSNL"), "9404":("Maharashtra","BSNL"),
    "9405":("Maharashtra","BSNL"), "9406":("Madhya Pradesh","BSNL"),
    "9407":("Madhya Pradesh","BSNL"), "9408":("Gujarat","BSNL"),
    "9410":("UP West","Airtel"), "9411":("UP West","Vodafone"),
    "9412":("UP West","Airtel"), "9413":("Rajasthan","Airtel"),
    "9414":("Rajasthan","Airtel"), "9415":("UP East","Airtel"),
    "9416":("Haryana","Airtel"), "9417":("Punjab","Airtel"),
    "9418":("Himachal Pradesh","Airtel"), "9419":("J&K","Airtel"),
    "9420":("Maharashtra","Airtel"), "9421":("Maharashtra","Airtel"),
    "9422":("Maharashtra","Vodafone"), "9423":("Maharashtra","Idea"),
    "9424":("Madhya Pradesh","Airtel"), "9425":("Madhya Pradesh","BSNL"),
    "9426":("Gujarat","Vodafone"), "9427":("Gujarat","Vodafone"),
    "9428":("Gujarat","BSNL"), "9429":("Gujarat","Idea"),
    "9430":("Bihar","Airtel"), "9431":("Bihar","Airtel"),
    "9432":("Kolkata","Vodafone"), "9433":("Kolkata","Airtel"),
    "9434":("West Bengal","BSNL"), "9435":("Assam","BSNL"),
    "9436":("North East","BSNL"), "9437":("Odisha","BSNL"),
    "9438":("Odisha","Airtel"), "9439":("Odisha","BSNL"),
    "9440":("Andhra Pradesh","Airtel"), "9441":("Andhra Pradesh","BSNL"),
    "9442":("Tamil Nadu","BSNL"), "9443":("Tamil Nadu","BSNL"),
    "9444":("Chennai","Vodafone"), "9445":("Tamil Nadu","BSNL"),
    "9446":("Kerala","BSNL"), "9447":("Kerala","BSNL"),
    "9448":("Karnataka","BSNL"), "9449":("Karnataka","BSNL"),
    "9450":("UP East","Airtel"), "9451":("UP East","Airtel"),
    "9452":("UP East","BSNL"), "9453":("UP East","Vodafone"),
    "9454":("UP East","BSNL"), "9455":("UP East","BSNL"),
    "9456":("UP West","BSNL"), "9457":("UP West","BSNL"),
    "9458":("UP West","Vodafone"), "9459":("Himachal Pradesh","BSNL"),
    "9460":("Rajasthan","BSNL"), "9461":("Rajasthan","BSNL"),
    "9462":("Rajasthan","BSNL"), "9463":("Punjab","BSNL"),
    "9464":("Punjab","BSNL"), "9465":("Punjab","BSNL"),
    "9466":("Haryana","BSNL"), "9467":("Haryana","BSNL"),
    "9468":("Haryana","BSNL"), "9469":("J&K","BSNL"),
    "9470":("Bihar","BSNL"), "9471":("Bihar","BSNL"),
    "9472":("Bihar","BSNL"), "9473":("Bihar","BSNL"),
    "9474":("West Bengal","BSNL"), "9475":("West Bengal","BSNL"),
    "9476":("West Bengal","BSNL"), "9477":("West Bengal","BSNL"),
    "9478":("Punjab","Vodafone"), "9479":("Madhya Pradesh","BSNL"),
    "9480":("Karnataka","Airtel"), "9481":("Karnataka","BSNL"),
    "9482":("Karnataka","BSNL"), "9483":("Karnataka","Vodafone"),
    "9484":("Gujarat","BSNL"), "9485":("Assam","BSNL"),
    "9486":("Tamil Nadu","BSNL"), "9487":("Chennai","Airtel"),
    "9488":("Tamil Nadu","Aircel"), "9489":("Tamil Nadu","BSNL"),
    "9490":("Andhra Pradesh","BSNL"), "9491":("Andhra Pradesh","BSNL"),
    "9492":("Andhra Pradesh","BSNL"), "9493":("Andhra Pradesh","BSNL"),
    "9494":("Andhra Pradesh","BSNL"), "9495":("Kerala","Airtel"),
    "9496":("Kerala","Airtel"), "9497":("Kerala","Vodafone"),
    "9498":("Andhra Pradesh","Aircel"), "9499":("Haryana","Vodafone"),
    "9500":("Chennai","Airtel"), "9501":("Punjab","Airtel"),
    "9502":("Andhra Pradesh","Airtel"), "9503":("Maharashtra","Vodafone"),
    "9504":("Bihar","Airtel"), "9505":("Andhra Pradesh","Airtel"),
    "9506":("UP East","Vodafone"), "9507":("Bihar","Vodafone"),
    "9508":("Bihar","Vodafone"), "9509":("Rajasthan","Vodafone"),
    "9510":("Gujarat","Reliance Jio"), "9511":("Rajasthan","Reliance Jio"),
    "9538":("Karnataka","Vodafone"), "9540":("Delhi","Aircel"),
    "9560":("Delhi","Airtel"), "9561":("Maharashtra","Idea"),
    "9583":("Odisha","Aircel"), "9584":("Madhya Pradesh","Aircel"),
    "9599":("Delhi","Aircel"),
    "9600":("Chennai","Airtel"), "9601":("Gujarat","Idea"),
    "9602":("Rajasthan","Idea"), "9603":("Andhra Pradesh","Idea"),
    "9604":("Maharashtra","Idea"), "9605":("Kerala","Idea"),
    "9606":("Karnataka","Idea"), "9611":("Karnataka","Airtel"),
    "9614":("Kolkata","Uninor"), "9615":("UP East","Uninor"),
    "9616":("UP East","Uninor"), "9617":("Madhya Pradesh","Vodafone"),
    "9618":("Andhra Pradesh","Idea"), "9619":("Mumbai","Vodafone"),
    "9620":("Karnataka","Airtel"), "9621":("UP East","Vodafone"),
    "9622":("J&K","Airtel"), "9623":("Maharashtra","Idea"),
    "9624":("Gujarat","Idea"), "9625":("Delhi","Idea"),
    "9626":("Tamil Nadu","Idea"), "9627":("UP West","Idea"),
    "9628":("UP East","Idea"), "9629":("Tamil Nadu","Airtel"),
    "9630":("Madhya Pradesh","Idea"), "9631":("Bihar","Idea"),
    "9632":("Karnataka","Airtel"), "9633":("Kerala","Idea"),
    "9634":("UP West","Idea"), "9635":("Kolkata","Idea"),
    "9636":("Rajasthan","Idea"), "9637":("Maharashtra","Idea"),
    "9638":("Gujarat","Idea"), "9639":("UP West","Idea"),
    "9640":("Andhra Pradesh","Idea"), "9641":("West Bengal","Idea"),
    "9642":("Andhra Pradesh","Idea"), "9643":("Delhi","Idea"),
    "9644":("Madhya Pradesh","Idea"), "9645":("Kerala","Idea"),
    "9646":("Punjab","Idea"), "9647":("Kolkata","Idea"),
    "9648":("UP East","Idea"), "9649":("Rajasthan","Idea"),
    "9650":("Delhi","Vodafone"), "9651":("UP East","Idea"),
    "9652":("Andhra Pradesh","Idea"), "9653":("Rajasthan","Idea"),
    "9654":("Delhi","Vodafone"), "9655":("Tamil Nadu","Idea"),
    "9656":("Kerala","Idea"), "9657":("Maharashtra","Idea"),
    "9658":("Odisha","Idea"), "9659":("Chennai","Idea"),
    "9660":("Rajasthan","Idea"), "9661":("Bihar","Idea"),
    "9662":("Gujarat","Idea"), "9663":("Karnataka","Idea"),
    "9664":("Rajasthan","Idea"), "9665":("Maharashtra","Idea"),
    "9666":("Andhra Pradesh","Idea"), "9667":("Delhi","Idea"),
    "9668":("Odisha","Idea"), "9669":("Madhya Pradesh","Idea"),
    "9670":("UP East","Vodafone"), "9671":("Haryana","Vodafone"),
    "9672":("Rajasthan","Vodafone"), "9673":("Maharashtra","Vodafone"),
    "9674":("Kolkata","Vodafone"), "9675":("UP West","Vodafone"),
    "9676":("Andhra Pradesh","Vodafone"), "9677":("Tamil Nadu","Vodafone"),
    "9678":("Assam","Vodafone"), "9679":("West Bengal","Vodafone"),
    "9680":("Rajasthan","Vodafone"), "9681":("Kolkata","Airtel"),
    "9682":("Assam","Airtel"), "9683":("Kolkata","Vodafone"),
    "9684":("West Bengal","Vodafone"), "9685":("Madhya Pradesh","Vodafone"),
    "9686":("Karnataka","Vodafone"), "9687":("Gujarat","Vodafone"),
    "9688":("Tamil Nadu","Vodafone"), "9689":("Maharashtra","Vodafone"),
    "9690":("UP West","Airtel"), "9691":("Madhya Pradesh","Airtel"),
    "9692":("Odisha","Airtel"), "9693":("Bihar","Airtel"),
    "9694":("Rajasthan","Airtel"), "9695":("UP East","Airtel"),
    "9696":("UP East","Vodafone"), "9697":("J&K","Vodafone"),
    "9698":("Tamil Nadu","Vodafone"), "9699":("Mumbai","Vodafone"),
    "9700":("Andhra Pradesh","Airtel"), "9701":("Andhra Pradesh","Airtel"),
    "9702":("Mumbai","Airtel"), "9703":("Andhra Pradesh","Airtel"),
    "9704":("Andhra Pradesh","Vodafone"), "9705":("Andhra Pradesh","Airtel"),
    "9706":("Assam","Aircel"), "9707":("North East","Airtel"),
    "9708":("Bihar","Vodafone"), "9709":("Bihar","Airtel"),
    "9710":("Chennai","Aircel"), "9711":("Delhi","Airtel"),
    "9712":("Gujarat","Vodafone"), "9713":("Madhya Pradesh","Vodafone"),
    "9714":("Gujarat","Idea"), "9715":("Tamil Nadu","Aircel"),
    "9716":("Delhi","Airtel"), "9717":("Delhi","Airtel"),
    "9718":("Delhi","Airtel"), "9719":("UP West","Airtel"),
    "9720":("UP West","Airtel"), "9721":("UP East","Airtel"),
    "9722":("Gujarat","Vodafone"), "9723":("Gujarat","Vodafone"),
    "9724":("Gujarat","Idea"), "9725":("Gujarat","Vodafone"),
    "9726":("Gujarat","Vodafone"), "9727":("Gujarat","Vodafone"),
    "9728":("Haryana","Airtel"), "9729":("Haryana","Airtel"),
    "9730":("Maharashtra","Airtel"), "9731":("Karnataka","Airtel"),
    "9732":("West Bengal","Airtel"), "9733":("West Bengal","Airtel"),
    "9734":("West Bengal","Airtel"), "9735":("West Bengal","Airtel"),
    "9736":("Himachal Pradesh","Vodafone"), "9737":("Gujarat","Idea"),
    "9738":("Karnataka","Airtel"), "9739":("Karnataka","Airtel"),
    "9740":("Karnataka","Airtel"), "9741":("Karnataka","Airtel"),
    "9742":("Karnataka","Airtel"), "9743":("Karnataka","Airtel"),
    "9744":("Kerala","Airtel"), "9745":("Kerala","Aircel"),
    "9746":("Kerala","Idea"), "9747":("Kerala","Airtel"),
    "9748":("Kolkata","Airtel"), "9749":("West Bengal","Airtel"),
    "9750":("Tamil Nadu","Airtel"), "9751":("Tamil Nadu","Airtel"),
    "9752":("Madhya Pradesh","Airtel"), "9753":("Madhya Pradesh","Airtel"),
    "9754":("Madhya Pradesh","Airtel"), "9755":("Madhya Pradesh","Airtel"),
    "9756":("UP West","Airtel"), "9757":("Maharashtra","Vodafone"),
    "9758":("UP West","Vodafone"), "9759":("UP West","Vodafone"),
    "9760":("UP West","Vodafone"), "9761":("UP West","Vodafone"),
    "9762":("Maharashtra","Idea"), "9763":("Maharashtra","Vodafone"),
    "9764":("Maharashtra","Idea"), "9765":("Maharashtra","Idea"),
    "9766":("Maharashtra","Idea"), "9767":("Maharashtra","Vodafone"),
    "9768":("Mumbai","Vodafone"), "9769":("Mumbai","Vodafone"),
    "9770":("Chhattisgarh","Airtel"), "9771":("Bihar","Airtel"),
    "9772":("Rajasthan","Airtel"), "9773":("Mumbai","Vodafone"),
    "9774":("Assam","Airtel"), "9775":("Kolkata","Idea"),
    "9776":("Odisha","Idea"), "9777":("Odisha","Vodafone"),
    "9778":("Kerala","Idea"), "9779":("Punjab","Airtel"),
    "9780":("Punjab","Airtel"), "9781":("Punjab","Airtel"),
    "9782":("Rajasthan","Airtel"), "9783":("Rajasthan","Airtel"),
    "9784":("Rajasthan","Airtel"), "9785":("Rajasthan","Airtel"),
    "9786":("Tamil Nadu","Aircel"), "9787":("Tamil Nadu","Aircel"),
    "9788":("Tamil Nadu","Aircel"), "9789":("Chennai","Aircel"),
    "9790":("Chennai","Airtel"), "9791":("Tamil Nadu","Airtel"),
    "9792":("UP East","Airtel"), "9793":("UP East","Idea"),
    "9794":("UP East","Idea"), "9795":("UP East","Idea"),
    "9796":("J&K","Vodafone"), "9797":("J&K","Airtel"),
    "9798":("Bihar","Airtel"), "9799":("Rajasthan","Airtel"),
    "9800":("Kolkata","Vodafone"), "9801":("Bihar","Vodafone"),
    "9802":("Haryana","Airtel"), "9803":("Punjab","Airtel"),
    "9804":("Kolkata","Vodafone"), "9805":("Himachal Pradesh","Airtel"),
    "9806":("Madhya Pradesh","Airtel"), "9807":("UP East","Vodafone"),
    "9808":("UP East","Airtel"), "9809":("Kerala","Vodafone"),
    "9810":("Delhi","Airtel"), "9811":("Delhi","Airtel"),
    "9812":("Haryana","Airtel"), "9813":("Haryana","Vodafone"),
    "9814":("Punjab","Airtel"), "9815":("Punjab","Airtel"),
    "9816":("Himachal Pradesh","Airtel"), "9817":("Haryana","Vodafone"),
    "9818":("Delhi","Airtel"), "9819":("Mumbai","Vodafone"),
    "9820":("Mumbai","Vodafone"), "9821":("Mumbai","Vodafone"),
    "9822":("Maharashtra","Airtel"), "9823":("Maharashtra","Airtel"),
    "9824":("Gujarat","Vodafone"), "9825":("Gujarat","Vodafone"),
    "9826":("Madhya Pradesh","Airtel"), "9827":("Madhya Pradesh","Vodafone"),
    "9828":("Rajasthan","Vodafone"), "9829":("Rajasthan","Airtel"),
    "9830":("Kolkata","Vodafone"), "9831":("Kolkata","Vodafone"),
    "9832":("West Bengal","Vodafone"), "9833":("Mumbai","Vodafone"),
    "9834":("Maharashtra","Vodafone"), "9835":("Bihar","Airtel"),
    "9836":("Kolkata","Vodafone"), "9837":("UP West","Airtel"),
    "9838":("UP East","Airtel"), "9839":("UP East","Airtel"),
    "9840":("Chennai","Airtel"), "9841":("Chennai","Airtel"),
    "9842":("Tamil Nadu","Airtel"), "9843":("Tamil Nadu","Airtel"),
    "9844":("Karnataka","Airtel"), "9845":("Karnataka","Airtel"),
    "9846":("Kerala","Vodafone"), "9847":("Kerala","Vodafone"),
    "9848":("Andhra Pradesh","Airtel"), "9849":("Andhra Pradesh","Airtel"),
    "9850":("Maharashtra","Airtel"), "9851":("Kolkata","Airtel"),
    "9852":("Bihar","Airtel"), "9853":("Odisha","Airtel"),
    "9854":("Assam","Airtel"), "9855":("Punjab","Airtel"),
    "9856":("North East","Airtel"), "9857":("Himachal Pradesh","Vodafone"),
    "9858":("J&K","Airtel"), "9859":("North East","Vodafone"),
    "9860":("Maharashtra","Airtel"), "9861":("Odisha","Airtel"),
    "9862":("North East","Airtel"), "9863":("North East","Airtel"),
    "9864":("Assam","Vodafone"), "9865":("Tamil Nadu","Aircel"),
    "9866":("Andhra Pradesh","Vodafone"), "9867":("Mumbai","Vodafone"),
    "9868":("Delhi","Airtel"), "9869":("Mumbai","Vodafone"),
    "9870":("Delhi","Vodafone"), "9871":("Delhi","Airtel"),
    "9872":("Punjab","Airtel"), "9873":("Delhi","Vodafone"),
    "9874":("Kolkata","Vodafone"), "9875":("Rajasthan","Vodafone"),
    "9876":("Punjab","Airtel"), "9877":("Punjab","Airtel"),
    "9878":("Punjab","Airtel"), "9879":("Gujarat","Vodafone"),
    "9880":("Karnataka","Airtel"), "9881":("Maharashtra","Vodafone"),
    "9882":("Himachal Pradesh","Vodafone"), "9883":("Kolkata","Vodafone"),
    "9884":("Chennai","Aircel"), "9885":("Andhra Pradesh","Airtel"),
    "9886":("Karnataka","Airtel"), "9887":("Rajasthan","Airtel"),
    "9888":("Punjab","Airtel"), "9889":("UP East","Airtel"),
    "9890":("Maharashtra","Airtel"), "9891":("Delhi","Airtel"),
    "9892":("Mumbai","Vodafone"), "9893":("Madhya Pradesh","Vodafone"),
    "9894":("Tamil Nadu","Aircel"), "9895":("Kerala","Vodafone"),
    "9896":("Haryana","Airtel"), "9897":("UP West","Airtel"),
    "9898":("Gujarat","Vodafone"), "9899":("Delhi","Airtel"),
    "9900":("Karnataka","Airtel"), "9901":("Karnataka","Airtel"),
    "9902":("Karnataka","Airtel"), "9903":("Kolkata","Aircel"),
    "9904":("Gujarat","Idea"), "9905":("Bihar","Airtel"),
    "9906":("J&K","Airtel"), "9907":("Madhya Pradesh","Vodafone"),
    "9908":("Andhra Pradesh","Airtel"), "9909":("Gujarat","Vodafone"),
    "9910":("Delhi","Airtel"), "9911":("Delhi","Airtel"),
    "9912":("Andhra Pradesh","Airtel"), "9913":("Gujarat","Airtel"),
    "9914":("Punjab","Airtel"), "9915":("Punjab","Airtel"),
    "9916":("Karnataka","Airtel"), "9917":("UP West","Airtel"),
    "9918":("UP East","Airtel"), "9919":("UP East","Airtel"),
    "9920":("Mumbai","Vodafone"), "9921":("Maharashtra","Airtel"),
    "9922":("Maharashtra","Airtel"), "9923":("Maharashtra","Airtel"),
    "9924":("Gujarat","Vodafone"), "9925":("Gujarat","Airtel"),
    "9926":("Madhya Pradesh","Vodafone"), "9927":("UP West","Airtel"),
    "9928":("Rajasthan","Airtel"), "9929":("Rajasthan","Airtel"),
    "9930":("Mumbai","Airtel"), "9931":("Bihar","Airtel"),
    "9932":("Kolkata","Airtel"), "9933":("Kolkata","Aircel"),
    "9934":("Bihar","Airtel"), "9935":("UP East","Airtel"),
    "9936":("UP East","Airtel"), "9937":("Odisha","Airtel"),
    "9938":("Odisha","Airtel"), "9939":("Bihar","Airtel"),
    "9940":("Chennai","Airtel"), "9941":("Chennai","Airtel"),
    "9942":("Tamil Nadu","Airtel"), "9943":("Tamil Nadu","Aircel"),
    "9944":("Tamil Nadu","Aircel"), "9945":("Karnataka","Airtel"),
    "9946":("Kerala","Airtel"), "9947":("Kerala","Airtel"),
    "9948":("Andhra Pradesh","Airtel"), "9949":("Andhra Pradesh","Airtel"),
    "9950":("Rajasthan","Airtel"), "9951":("Andhra Pradesh","Airtel"),
    "9952":("Tamil Nadu","Aircel"), "9953":("Delhi","Airtel"),
    "9954":("Assam","Airtel"), "9955":("Bihar","Airtel"),
    "9956":("UP East","Airtel"), "9957":("Assam","Airtel"),
    "9958":("Delhi","Airtel"), "9959":("Andhra Pradesh","Airtel"),
    "9960":("Maharashtra","Airtel"), "9961":("Kerala","Airtel"),
    "9962":("Chennai","Aircel"), "9963":("Andhra Pradesh","Airtel"),
    "9964":("Karnataka","Airtel"), "9965":("Tamil Nadu","Aircel"),
    "9966":("Andhra Pradesh","Airtel"), "9967":("Mumbai","Vodafone"),
    "9968":("Delhi","Airtel"), "9969":("Mumbai","Vodafone"),
    "9970":("Maharashtra","Airtel"), "9971":("Delhi","Vodafone"),
    "9972":("Karnataka","Airtel"), "9973":("Bihar","Airtel"),
    "9974":("Gujarat","Vodafone"), "9975":("Maharashtra","Airtel"),
    "9976":("Tamil Nadu","Aircel"), "9977":("Madhya Pradesh","Vodafone"),
    "9978":("Gujarat","Vodafone"), "9979":("Gujarat","Vodafone"),
    "9980":("Karnataka","Airtel"), "9981":("Madhya Pradesh","Vodafone"),
    "9982":("Rajasthan","Airtel"), "9983":("Rajasthan","Vodafone"),
    "9984":("UP East","Airtel"), "9985":("Andhra Pradesh","Airtel"),
    "9986":("Karnataka","Airtel"), "9987":("Mumbai","Vodafone"),
    "9988":("Punjab","Airtel"), "9989":("Andhra Pradesh","Airtel"),
    "9990":("Delhi","Airtel"), "9991":("Haryana","Airtel"),
    "9992":("Haryana","Airtel"), "9993":("Madhya Pradesh","Vodafone"),
    "9994":("Tamil Nadu","Aircel"), "9995":("Kerala","Airtel"),
    "9996":("Haryana","Airtel"), "9997":("UP West","Airtel"),
    "9998":("Gujarat","Vodafone"), "9999":("Delhi","Airtel"),
}

def _lookup_india_circle(national_number: str) -> Optional[tuple]:
    """Return (circle_name, original_operator) or None. Matches by first 4 digits."""
    key = national_number[:4]
    return INDIA_CIRCLES.get(key)

# ─── Module 2: Phone Number Intelligence (Numint-style deep OSINT) ───────────

class PhoneIntel:
    """Deep phone OSINT — parse, carrier, geo, line type, messenger presence,
    reputation, OSINT dorks, format variants. Inspired by Numint / PhoneInfoga."""

    # Country → ISO2 flag (for a subset — extend as needed)
    COUNTRY_FLAGS = {
        1: "🇺🇸", 7: "🇷🇺", 20: "🇪🇬", 27: "🇿🇦", 30: "🇬🇷", 31: "🇳🇱",
        32: "🇧🇪", 33: "🇫🇷", 34: "🇪🇸", 36: "🇭🇺", 39: "🇮🇹", 40: "🇷🇴",
        41: "🇨🇭", 43: "🇦🇹", 44: "🇬🇧", 45: "🇩🇰", 46: "🇸🇪", 47: "🇳🇴",
        48: "🇵🇱", 49: "🇩🇪", 51: "🇵🇪", 52: "🇲🇽", 54: "🇦🇷", 55: "🇧🇷",
        56: "🇨🇱", 57: "🇨🇴", 58: "🇻🇪", 60: "🇲🇾", 61: "🇦🇺", 62: "🇮🇩",
        63: "🇵🇭", 64: "🇳🇿", 65: "🇸🇬", 66: "🇹🇭", 81: "🇯🇵", 82: "🇰🇷",
        84: "🇻🇳", 86: "🇨🇳", 90: "🇹🇷", 91: "🇮🇳", 92: "🇵🇰", 93: "🇦🇫",
        94: "🇱🇰", 95: "🇲🇲", 98: "🇮🇷", 212: "🇲🇦", 213: "🇩🇿", 216: "🇹🇳",
        218: "🇱🇾", 220: "🇬🇲", 234: "🇳🇬", 254: "🇰🇪", 260: "🇿🇲",
        263: "🇿🇼", 351: "🇵🇹", 352: "🇱🇺", 353: "🇮🇪", 358: "🇫🇮",
        370: "🇱🇹", 371: "🇱🇻", 380: "🇺🇦", 420: "🇨🇿", 421: "🇸🇰",
        852: "🇭🇰", 880: "🇧🇩", 886: "🇹🇼", 966: "🇸🇦", 971: "🇦🇪",
        972: "🇮🇱", 974: "🇶🇦", 977: "🇳🇵", 992: "🇹🇯", 994: "🇦🇿",
    }

    # Approx country centroids (lat, lon) — for map pivots when only country is known
    COUNTRY_COORDS = {
        1:  (37.0902, -95.7129),   7:  (61.5240, 105.3188),  20: (26.8206, 30.8025),
        27: (-30.5595, 22.9375),   30: (39.0742, 21.8243),   31: (52.1326, 5.2913),
        32: (50.5039, 4.4699),     33: (46.2276, 2.2137),    34: (40.4637, -3.7492),
        36: (47.1625, 19.5033),    39: (41.8719, 12.5674),   40: (45.9432, 24.9668),
        41: (46.8182, 8.2275),     43: (47.5162, 14.5501),   44: (55.3781, -3.4360),
        45: (56.2639, 9.5018),     46: (60.1282, 18.6435),   47: (60.4720, 8.4689),
        48: (51.9194, 19.1451),    49: (51.1657, 10.4515),   52: (23.6345, -102.5528),
        55: (-14.2350, -51.9253),  60: (4.2105, 101.9758),   61: (-25.2744, 133.7751),
        62: (-0.7893, 113.9213),   63: (12.8797, 121.7740),  65: (1.3521, 103.8198),
        66: (15.8700, 100.9925),   81: (36.2048, 138.2529),  82: (35.9078, 127.7669),
        84: (14.0583, 108.2772),   86: (35.8617, 104.1954),  90: (38.9637, 35.2433),
        91: (20.5937, 78.9629),    92: (30.3753, 69.3451),   94: (7.8731, 80.7718),
        95: (21.9162, 95.9560),    98: (32.4279, 53.6880),  212: (31.7917, -7.0926),
        234: (9.0820, 8.6753),    254: (-0.0236, 37.9062),  351: (39.3999, -8.2245),
        352: (49.8153, 6.1296),   353: (53.4129, -8.2439),  358: (61.9241, 25.7482),
        380: (48.3794, 31.1656),  420: (49.8175, 15.4730),  421: (48.6690, 19.6990),
        852: (22.3193, 114.1694), 880: (23.6850, 90.3563),  886: (23.6978, 120.9605),
        966: (23.8859, 45.0792),  971: (23.4241, 53.8478),  972: (31.0461, 34.8516),
        974: (25.3548, 51.1839),  977: (28.3949, 84.1240),
    }

    OSINT_ENGINES = [
        ("Google",     "https://www.google.com/search?q=%22{q}%22"),
        ("DuckDuckGo", "https://duckduckgo.com/?q=%22{q}%22"),
        ("Bing",       "https://www.bing.com/search?q=%22{q}%22"),
        ("Yandex",     "https://yandex.com/search/?text=%22{q}%22"),
        ("Facebook",   "https://www.facebook.com/search/top/?q={q}"),
        ("LinkedIn",   "https://www.linkedin.com/search/results/all/?keywords={q}"),
        ("Twitter/X",  "https://twitter.com/search?q=%22{q}%22"),
        ("Truecaller", "https://www.truecaller.com/search/{cc}/{nat}"),
        ("Pastebin",   "https://www.google.com/search?q=site%3Apastebin.com+%22{q}%22"),
        ("GitHub",     "https://github.com/search?q=%22{q}%22&type=code"),
    ]

    @staticmethod
    def _flag(cc: int) -> str:
        return PhoneIntel.COUNTRY_FLAGS.get(cc, "🏳️")

    @staticmethod
    def _osint_links(e164: str, country_code: int, national: str) -> list[dict]:
        q = e164.replace("+", "")
        return [
            {"engine": name,
             "url": url.format(q=q, cc=country_code, nat=national)}
            for name, url in PhoneIntel.OSINT_ENGINES
        ]

    @staticmethod
    def _format_variants(parsed) -> dict:
        F = phonenumbers.PhoneNumberFormat
        fmt = phonenumbers.format_number
        return {
            "e164":          fmt(parsed, F.E164),
            "international": fmt(parsed, F.INTERNATIONAL),
            "national":      fmt(parsed, F.NATIONAL),
            "rfc3966":       fmt(parsed, F.RFC3966),
        }

    @staticmethod
    def _messenger_links(e164: str) -> dict:
        """Direct-open URLs for major messengers. Existence isn't confirmed
        (that requires authenticated APIs) — these are actionable pivots."""
        num = e164.replace("+", "")
        return {
            "whatsapp":  f"https://wa.me/{num}",
            "telegram":  f"https://t.me/+{num}",
            "signal":    f"https://signal.me/#p/{e164}",
            "viber":     f"viber://chat?number={e164}",
            "skype":     f"skype:{e164}?call",
            "sms":       f"sms:{e164}",
            "tel":       f"tel:{e164}",
        }

    @staticmethod
    async def _check_messenger_presence(session, e164: str) -> dict:
        """Best-effort HEAD probes to public messenger endpoints — signals
        only, never definitive. WhatsApp/Telegram/Viber require auth to
        confirm registration; response codes are informational."""
        num = e164.replace("+", "")
        endpoints = {
            "whatsapp": f"https://wa.me/{num}",
            "telegram": f"https://t.me/+{num}",
        }
        results = {}
        for name, url in endpoints.items():
            try:
                async with session.head(url, allow_redirects=True, ssl=False,
                                        timeout=aiohttp.ClientTimeout(total=8)) as r:
                    results[name] = {"reachable": 200 <= r.status < 400,
                                     "status": r.status, "url": url}
            except Exception as e:
                results[name] = {"reachable": False, "error": str(e), "url": url}
        return results

    @staticmethod
    def _reputation_hints(line_type: str, carrier_name: str) -> list[str]:
        hints = []
        if line_type == "voip":
            hints.append("⚠️ VoIP — often used for OTP fraud / burner numbers")
        if line_type == "toll_free":
            hints.append("ℹ️ Toll-free — business/support line")
        if carrier_name and any(k in carrier_name.lower()
                                for k in ("google", "twilio", "bandwidth", "textnow")):
            hints.append("⚠️ Virtual carrier — high burner probability")
        return hints

    @staticmethod
    async def analyze(raw: str, session: aiohttp.ClientSession = None) -> dict:
        if not PHONE_AVAILABLE:
            return {"error": "phonenumbers library not installed"}
        try:
            parsed = phonenumbers.parse(raw, None)
        except Exception as e:
            return {"error": f"Parse error: {e}"}

        valid = phonenumbers.is_valid_number(parsed)
        possible = phonenumbers.is_possible_number(parsed)

        ntype = number_type(parsed)
        type_map = {
            phonenumbers.PhoneNumberType.MOBILE: "mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "landline",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_or_mobile",
            phonenumbers.PhoneNumberType.VOIP: "voip",
            phonenumbers.PhoneNumberType.TOLL_FREE: "toll_free",
            phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium_rate",
            phonenumbers.PhoneNumberType.SHARED_COST: "shared_cost",
            phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal",
            phonenumbers.PhoneNumberType.PAGER: "pager",
            phonenumbers.PhoneNumberType.UAN: "uan",
            phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
        }
        line_type = type_map.get(ntype, "unknown")
        car = carrier.name_for_number(parsed, "en") or "Unknown"
        region_iso = phonenumbers.region_code_for_number(parsed) or "??"
        region_name = geocoder.description_for_number(parsed, "en") or "Unknown"

        try:
            from phonenumbers import timezone as pn_tz
            timezones = list(pn_tz.time_zones_for_number(parsed))
        except Exception:
            timezones = []

        fmts = PhoneIntel._format_variants(parsed)
        national_str = str(parsed.national_number)

        # ── India-specific: originally-assigned telecom circle ──
        india_circle = None
        india_operator = None
        if parsed.country_code == 91:
            match = _lookup_india_circle(national_str)
            if match:
                india_circle, india_operator = match

        # ── Location intelligence ──
        coords = PhoneIntel.COUNTRY_COORDS.get(parsed.country_code)
        # Prefer geocoder's specific region (e.g. "Baghpat, UP") if it isn't
        # just the country name; else fall back to country name.
        specific = region_name if region_name and region_name.lower() != \
            _country_english_name(region_iso).lower() else None
        # Prefer India circle over phonenumbers geocoder when available
        if india_circle and not specific:
            specific = f"{india_circle} circle"
        map_query = (india_circle or specific or region_name or region_iso)
        location = {
            "specific_region": specific,
            "india_circle":    india_circle,
            "india_original_operator": india_operator,
            "country_name":    region_name if not specific else _country_english_name(region_iso),
            "region_iso":      region_iso,
            "coords":          {"lat": coords[0], "lon": coords[1]} if coords else None,
            "google_maps":     f"https://www.google.com/maps/search/{map_query.replace(' ', '+')}"
                                if map_query else None,
            "osm":             f"https://www.openstreetmap.org/search?query={map_query.replace(' ', '+')}"
                                if map_query else None,
        }
        if coords:
            location["maps_pin"] = f"https://www.google.com/maps/@{coords[0]},{coords[1]},6z"

        result = {
            "valid": valid,
            "possible": possible,
            "flag": PhoneIntel._flag(parsed.country_code),
            "formats": fmts,
            "country_code": parsed.country_code,
            "region_iso": region_iso,
            "region_name": region_name,
            "national_number": national_str,
            "carrier": car,
            "line_type": line_type,
            "timezones": timezones,
            "location": location,
            "messengers": PhoneIntel._messenger_links(fmts["e164"]),
            "reputation_hints": PhoneIntel._reputation_hints(line_type, car),
            "osint_dorks": PhoneIntel._osint_links(
                fmts["e164"], parsed.country_code, national_str
            ),
        }

        if session is not None:
            result["messenger_presence"] = \
                await PhoneIntel._check_messenger_presence(session, fmts["e164"])

        return result

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

    async def investigate_phone(self, session, phone: str) -> dict:
        log.info(f"[PHONE] Analyzing {phone}")
        return await PhoneIntel.analyze(phone, session)

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
                    tasks.append(self.investigate_phone(session, value))
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

def detect_type(value: str) -> Optional[str]:
    """Auto-detect target type from a raw value."""
    v = value.strip()
    if re.match(r'^https?://', v, re.IGNORECASE):
        return "url"
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', v):
        return "ip"
    if re.match(r'^[\w.+-]+@[\w-]+\.[a-z]{2,}$', v, re.IGNORECASE):
        return "email"
    if re.match(r'^\+?\d[\d\s\-().]{6,}$', v):
        return "phone"
    if v.lower().endswith((".jpg", ".jpeg", ".png", ".gif", ".webp", ".tiff")) \
            or Path(v).is_file():
        return "image"
    if "." in v and " " not in v and not v.startswith("@"):
        return "domain"
    return "username"

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ghostbuster",
        description="GhostBuster OSINT Framework — authorized penetration testing tool",
        epilog="Simple usage:  ghostbuster <target>   (type auto-detected)\n"
               "Explicit    :  ghostbuster phone +911234567890\n"
               "Bulk        :  ghostbuster bulk targets.txt",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", nargs="?", help="Target value (IP/domain/URL/email/phone/username/image) — type auto-detected")
    p.add_argument("value",  nargs="?", help=argparse.SUPPRESS)  # for explicit-type form: `ghostbuster phone +91...`
    p.add_argument("--type", "-t", choices=["ip","domain","url","username","email","phone","image"],
                   help="Force target type (skip auto-detection)")
    p.add_argument("--bulk", "-b", metavar="FILE", help="Bulk process a CSV/JSON/TXT file")
    p.add_argument("-c", "--config", default="config.yaml")
    p.add_argument("-o", "--output", default="ghostbuster_report")
    p.add_argument("-f", "--format", choices=["json","xml","both"], default="json")
    p.add_argument("--graph", action="store_true", help="Render relationship PNG")
    p.add_argument("--log-level", default="INFO")
    return p

# ─── Rich boxed panel renderer (Numint-style) ───────────────────────────────

def _visible_len(s: str) -> int:
    """Length of string with ANSI codes stripped."""
    return len(re.sub(r"\x1b\[[0-9;]*m", "", s))

def _panel(title: str, rows: list[tuple], width: int = 70,
           border_color: str = "\033[38;5;46m",
           title_color: str = "\033[38;5;46m",
           label_color: str = "\033[38;5;255m",
           value_color: str = "\033[38;5;51m") -> str:
    """Draw a boxed panel with a centered title and right-aligned labels.
    rows: list of (label, value) — value may already contain color codes."""
    R = "\033[0m"
    BOLD = "\033[1m"
    # Title bar: ╭─── Title ───╮
    title_txt = f" {BOLD}{title_color}{title}{R} "
    tvis = _visible_len(title_txt)
    side = max(0, (width - 2 - tvis) // 2)
    left_dashes = "─" * side
    right_dashes = "─" * (width - 2 - side - tvis)
    top = f"{border_color}╭{left_dashes}{R}{title_txt}{border_color}{right_dashes}╮{R}"
    bot = f"{border_color}╰{'─' * (width - 2)}╯{R}"

    # Widest label for right-alignment
    max_label = max((_visible_len(l) for l, _ in rows), default=0)

    lines = [top]
    for label, value in rows:
        pad_label = " " * (max_label - _visible_len(label))
        line_content = f"  {pad_label}{label_color}{label}{R}  {value}{R}"
        inner_len = _visible_len(line_content)
        trailing = " " * max(0, width - 2 - inner_len)
        lines.append(f"{border_color}│{R}{line_content}{trailing}{border_color}│{R}")
    lines.append(bot)
    return "\n".join(lines)


def _render_phone_panels(target: str, data: dict):
    G = "\033[38;5;46m"    # green
    O = "\033[38;5;208m"   # orange
    C = "\033[38;5;51m"    # cyan
    Y = "\033[38;5;226m"   # yellow
    RED = "\033[38;5;196m"
    W = "\033[38;5;255m"
    D = "\033[38;5;240m"
    R = "\033[0m"

    if data.get("error"):
        print(f"\n{RED}  ✗ {data['error']}{R}\n")
        return

    fmts   = data.get("formats", {})
    flag   = data.get("flag", "🏳️")
    valid  = data.get("valid")
    poss   = data.get("possible")
    valid_str = f"{G}VALID{R}" if valid else f"{RED}INVALID{R}"

    # ── Panel 1: Intelligence Profile ──
    rows1 = [
        ("Number",   f"{C}{fmts.get('e164', target)}{R}"),
        ("National", f"{W}{fmts.get('national', '?')}{R}"),
        ("Country",  f"{flag}  {W}{data.get('region_name','?')} "
                     f"{D}({data.get('region_iso','??')} · +{data.get('country_code','?')}){R}"),
        ("Type",     f"{Y}{data.get('line_type','?')}{R}"),
        ("Validity", valid_str),
        ("Carrier",  f"{W}{data.get('carrier') or 'unknown'}{R}"),
    ]
    tz = data.get("timezones", [])
    if tz:
        rows1.append(("Timezone", f"{W}{', '.join(tz)}{R}"))
    for hint in data.get("reputation_hints", []):
        rows1.append(("Note", f"{Y}{hint}{R}"))

    print()
    print(_panel("Intelligence Profile", rows1, width=72,
                 border_color=G, title_color=G))

    # ── Panel 2: Validity & Format ──
    rows2 = [
        ("E.164",         f"{C}{fmts.get('e164','?')}{R}"),
        ("International", f"{W}{fmts.get('international','?')}{R}"),
        ("National",      f"{W}{fmts.get('national','?')}{R}"),
        ("RFC3966",       f"{D}{fmts.get('rfc3966','?')}{R}"),
        ("Possible",      f"{G}yes{R}" if poss  else f"{RED}no{R}"),
        ("Valid",         f"{G}yes{R}" if valid else f"{RED}no{R}"),
    ]
    print(_panel("Validity & Format", rows2, width=72,
                 border_color=O, title_color=O))

    # ── Panel 3: Location Intelligence ──
    loc = data.get("location", {})
    if loc:
        rows_loc = []
        if loc.get("india_circle"):
            rows_loc.append(("Circle",  f"{Y}📍 {loc['india_circle']} {D}(state/region){R}"))
            if loc.get("india_original_operator"):
                rows_loc.append(("Original Op", f"{W}{loc['india_original_operator']} "
                                                f"{D}(pre-MNP assignment){R}"))
        elif loc.get("specific_region"):
            rows_loc.append(("Region",  f"{Y}📍 {loc['specific_region']}{R}"))
        rows_loc.append(("Country",     f"{W}{loc.get('country_name','?')} "
                                        f"{D}({loc.get('region_iso','??')}){R}"))
        c = loc.get("coords")
        if c:
            rows_loc.append(("Coords",  f"{C}{c['lat']:.4f}, {c['lon']:.4f}{R}  "
                                        f"{D}(country centroid){R}"))
        if loc.get("google_maps"):
            rows_loc.append(("Google Maps", f"{D}{loc['google_maps']}{R}"))
        if loc.get("maps_pin"):
            rows_loc.append(("Map Pin",     f"{D}{loc['maps_pin']}{R}"))
        if loc.get("osm"):
            rows_loc.append(("OpenStreetMap", f"{D}{loc['osm']}{R}"))
        print(_panel("Location Intelligence", rows_loc, width=90,
                     border_color="\033[38;5;213m",  # pink
                     title_color="\033[38;5;213m"))

    # ── Panel 4: Messenger Presence ──
    mp = data.get("messenger_presence", {})
    msg = data.get("messengers", {})
    if mp or msg:
        rows3 = []
        for name in ("whatsapp", "telegram"):
            if name in mp:
                r = mp[name]
                ok = r.get("reachable")
                mark = f"{G}✓ reachable{R}" if ok else f"{RED}✗ unreachable{R}"
                rows3.append((name.capitalize(), f"{mark}  {D}({r.get('status','?')}){R}"))
        for name in ("signal", "viber", "skype", "sms", "tel"):
            if name in msg:
                rows3.append((name.capitalize(), f"{D}{msg[name]}{R}"))
        print(_panel("Messenger Presence & Pivots", rows3, width=72,
                     border_color=C, title_color=C))

    # ── Panel 4: OSINT Search Links ──
    dorks = data.get("osint_dorks", [])
    if dorks:
        rows4 = [(d["engine"], f"{D}{d['url']}{R}") for d in dorks]
        print(_panel(f"OSINT Search Dorks ({len(dorks)})", rows4, width=90,
                     border_color=Y, title_color=Y))
    print()


async def main_async(args):
    config = load_config(args.config)
    config["graph"] = args.graph
    setup_logging(level=args.log_level)

    # Bulk mode
    if args.bulk:
        targets = parse_bulk_file(args.bulk)
    # Explicit form:  ghostbuster phone +91...
    elif args.target in ("ip","domain","url","username","email","phone","image") and args.value:
        targets = [{"type": args.target, "value": args.value}]
    # Simple form:    ghostbuster <value>  (auto-detect or --type)
    elif args.target:
        ttype = args.type or detect_type(args.target)
        if not ttype:
            log.error(f"Could not detect target type for: {args.target}")
            sys.exit(1)
        log.info(f"Auto-detected type: {ttype}")
        targets = [{"type": ttype, "value": args.target}]
    else:
        build_parser().print_help()
        sys.exit(1)

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
                _render_phone_panels(t["value"], data)

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
