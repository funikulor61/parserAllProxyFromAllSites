#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MULTI-SOURCE PROXY PARSER & CHECKER v2 (fully async, aiohttp)

Finds proxies from ~90 sources IN PARALLEL:
  - GitHub raw lists:  proxifly, TheSpeedX, monosans, zevtyardt, MuRongPIG,
    casals-ar, hookzof, vakhov, clarketm, roosterkid, hideip.me, sunny9577,
    mmpx12, jetkai, ProxyScraper, prxchk, VPSLab, MrMarble, proxio-io,
    proxmint, stormsia, themiralay, hproxy, ProxyScrape(json)
  - API endpoints:     proxyscrape.com, proxyspace.pro, geonode (2 pages),
    api.openproxylist.xyz, pubproxy.com
  - HTML tables:       free-proxy-list.net, sslproxies.org, us-proxy.org,
    uk-proxy.org, socks-proxy.net, google-proxy.net, freeproxy.world
  - Text pages:        spys.me

Then (quality pipeline):
  1) dedupe by ip:port (stronger scheme wins)
  2) PASS 1: fast check on 7 rotating echo endpoints (drops transparent
     proxies that echo our own IP)
  3) PASS 2 (verify): re-check survivors on non-Cloudflare endpoints
     (kills CF-edge fakes and one-shot flaky proxies)
  4) PASS 3 (connect): TLS CONNECT test via https:// -> marks which proxies
     really work for HTTPS
  5) PASS 4 (anonymity): fetch azenv.net header-echo through the proxy and
     classify elite / anonymous / transparent (transparent = leaks your IP = BAD)
  6) PASS 5 (geo): ip-api.com batch -> country, ISP + "bad" flags:
     proxy_flag (IP already known as proxy/VPN) and hosting (datacenter IP)
  7) output: working_all.txt + per-protocol files + working_elite.txt
     + working_all.csv with all quality columns

USAGE:
    python parserik.py                                  # everything, default
    python parserik.py --only http,https                # check only these schemes
    python parserik.py --limit 5000                     # check random 5000
    python parserik.py --concurrency 1000 --timeout 3   # faster / stricter
    python parserik.py --no-verify --no-geo --no-anonymity --no-connect   # speed mode
    python parserik.py --no-html --no-socks             # skip source groups

    

#python parserik.py --only http,https --concurrency 800 --max-latency 400
#python parserik.py --only http,https --concurrency 800 --timeout 4 --max-latency 400
#python parserik.py --only http,https --no-html --no-anonymity --no-geo --no-connect
REQUIRES:
    pip install aiohttp aiohttp-socks
"""

import argparse
import asyncio
import json
import os
import random
import re
import sys
import time
from collections import defaultdict

try:
    import aiohttp
except ImportError:
    sys.stderr.write("ERROR: 'aiohttp' is not installed.\n"
                     "Run: pip install aiohttp aiohttp-socks\n")
    sys.exit(1)

try:
    from aiohttp_socks import ProxyConnector
    SOCKS_SUPPORT = True
except ImportError:
    SOCKS_SUPPORT = False


# ===========================================================================
# SOURCES (kind: text | html | freeproxy | json)
#   text     - plain text, regex ip:port
#   html     - <td>ip</td><td>port</td> tables
#   freeproxy- freeproxy.world layout (port inside <a href="/?port=N">)
#   json     - any JSON with ip/port fields; per-entry protocol if present
# scheme = protocol claimed by the source; JSON entries may override it.
# ===========================================================================
GH = "https://raw.githubusercontent.com"

SOURCES = [
    # ---------- GitHub: proxifly (original source) ----------
    {"name": "proxifly/http",     "kind": "text", "scheme": "http",
     "url": f"{GH}/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt"},
    {"name": "proxifly/https",    "kind": "text", "scheme": "https",
     "url": f"{GH}/proxifly/free-proxy-list/main/proxies/protocols/https/data.txt"},
    {"name": "proxifly/socks4",   "kind": "text", "scheme": "socks4",
     "url": f"{GH}/proxifly/free-proxy-list/main/proxies/protocols/socks4/data.txt"},
    {"name": "proxifly/socks5",   "kind": "text", "scheme": "socks5",
     "url": f"{GH}/proxifly/free-proxy-list/main/proxies/protocols/socks5/data.txt"},
    # ---------- GitHub: TheSpeedX ----------
    {"name": "thespeedx/http",    "kind": "text", "scheme": "http",
     "url": f"{GH}/TheSpeedX/PROXY-List/master/http.txt"},
    {"name": "thespeedx/socks4",  "kind": "text", "scheme": "socks4",
     "url": f"{GH}/TheSpeedX/PROXY-List/master/socks4.txt"},
    {"name": "thespeedx/socks5",  "kind": "text", "scheme": "socks5",
     "url": f"{GH}/TheSpeedX/PROXY-List/master/socks5.txt"},
    # ---------- GitHub: monosans ----------
    {"name": "monosans/http",     "kind": "text", "scheme": "http",
     "url": f"{GH}/monosans/proxy-list/main/proxies/http.txt"},
    {"name": "monosans/socks4",   "kind": "text", "scheme": "socks4",
     "url": f"{GH}/monosans/proxy-list/main/proxies/socks4.txt"},
    {"name": "monosans/socks5",   "kind": "text", "scheme": "socks5",
     "url": f"{GH}/monosans/proxy-list/main/proxies/socks5.txt"},
    # ---------- GitHub: other big lists ----------
    {"name": "zevtyardt/all",    "kind": "text", "scheme": "http",
     "url": f"{GH}/zevtyardt/proxy-list/main/all.txt"},
    {"name": "murongpig/http",   "kind": "text", "scheme": "http",
     "url": f"{GH}/MuRongPIG/Proxy-Master/main/http.txt"},
    {"name": "casals-ar/http",    "kind": "text", "scheme": "http",
     "url": f"{GH}/casals-ar/proxy-list/main/http"},
    {"name": "casals-ar/https",   "kind": "text", "scheme": "https",
     "url": f"{GH}/casals-ar/proxy-list/main/https"},
    {"name": "casals-ar/socks5",  "kind": "text", "scheme": "socks5",
     "url": f"{GH}/casals-ar/proxy-list/main/socks5"},
    {"name": "hookzof/socks5",    "kind": "text", "scheme": "socks5",
     "url": f"{GH}/hookzof/socks5_list/master/proxy.txt"},
    {"name": "vakhov/http",       "kind": "text", "scheme": "http",
     "url": f"{GH}/vakhov/fresh-proxy-list/master/http.txt"},
    {"name": "vakhov/https",      "kind": "text", "scheme": "https",
     "url": f"{GH}/vakhov/fresh-proxy-list/master/https.txt"},
    {"name": "vakhov/socks4",     "kind": "text", "scheme": "socks4",
     "url": f"{GH}/vakhov/fresh-proxy-list/master/socks4.txt"},
    {"name": "vakhov/socks5",     "kind": "text", "scheme": "socks5",
     "url": f"{GH}/vakhov/fresh-proxy-list/master/socks5.txt"},
    {"name": "clarketm/http",     "kind": "text", "scheme": "http",
     "url": f"{GH}/clarketm/proxy-list/master/proxy-list-raw.txt"},
    {"name": "roosterkid/https",  "kind": "text", "scheme": "https",
     "url": f"{GH}/roosterkid/openproxylist/main/HTTPS_RAW.txt"},
    {"name": "roosterkid/socks4", "kind": "text", "scheme": "socks4",
     "url": f"{GH}/roosterkid/openproxylist/main/SOCKS4_RAW.txt"},
    {"name": "roosterkid/socks5", "kind": "text", "scheme": "socks5",
     "url": f"{GH}/roosterkid/openproxylist/main/SOCKS5_RAW.txt"},
    {"name": "hideip/http",       "kind": "text", "scheme": "http",
     "url": f"{GH}/zloi-user/hideip.me/main/http.txt"},
    {"name": "hideip/https",      "kind": "text", "scheme": "https",
     "url": f"{GH}/zloi-user/hideip.me/main/https.txt"},
    {"name": "hideip/socks4",     "kind": "text", "scheme": "socks4",
     "url": f"{GH}/zloi-user/hideip.me/main/socks4.txt"},
    {"name": "hideip/socks5",     "kind": "text", "scheme": "socks5",
     "url": f"{GH}/zloi-user/hideip.me/main/socks5.txt"},
    {"name": "sunny9577/http",    "kind": "text", "scheme": "http",
     "url": f"{GH}/sunny9577/proxy-scraper/master/generated/http_proxies.txt"},
    {"name": "mmpx12/http",       "kind": "text", "scheme": "http",
     "url": f"{GH}/mmpx12/proxy-list/master/http.txt"},
    {"name": "mmpx12/https",      "kind": "text", "scheme": "https",
     "url": f"{GH}/mmpx12/proxy-list/master/https.txt"},
    {"name": "mmpx12/socks4",     "kind": "text", "scheme": "socks4",
     "url": f"{GH}/mmpx12/proxy-list/master/socks4.txt"},
    {"name": "mmpx12/socks5",     "kind": "text", "scheme": "socks5",
     "url": f"{GH}/mmpx12/proxy-list/master/socks5.txt"},
    # ---------- GitHub: jetkai ----------
    {"name": "jetkai/http",       "kind": "text", "scheme": "http",
     "url": f"{GH}/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt"},
    {"name": "jetkai/https",      "kind": "text", "scheme": "https",
     "url": f"{GH}/jetkai/proxy-list/main/online-proxies/txt/proxies-https.txt"},
    {"name": "jetkai/socks4",     "kind": "text", "scheme": "socks4",
     "url": f"{GH}/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt"},
    {"name": "jetkai/socks5",     "kind": "text", "scheme": "socks5",
     "url": f"{GH}/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt"},
    # ---------- GitHub: ProxyScraper ----------
    {"name": "proxyscraper/http", "kind": "text", "scheme": "http",
     "url": f"{GH}/ProxyScraper/ProxyScraper/main/http.txt"},
    {"name": "proxyscraper/socks4", "kind": "text", "scheme": "socks4",
     "url": f"{GH}/ProxyScraper/ProxyScraper/main/socks4.txt"},
    {"name": "proxyscraper/socks5", "kind": "text", "scheme": "socks5",
     "url": f"{GH}/ProxyScraper/ProxyScraper/main/socks5.txt"},
    # ---------- GitHub: prxchk ----------
    {"name": "prxchk/http",       "kind": "text", "scheme": "http",
     "url": f"{GH}/prxchk/proxy-list/main/http.txt"},
    {"name": "prxchk/socks4",     "kind": "text", "scheme": "socks4",
     "url": f"{GH}/prxchk/proxy-list/main/socks4.txt"},
    {"name": "prxchk/socks5",     "kind": "text", "scheme": "socks5",
     "url": f"{GH}/prxchk/proxy-list/main/socks5.txt"},
    # ---------- GitHub: VPSLab ----------
    {"name": "vpslab/http",       "kind": "text", "scheme": "http",
     "url": f"{GH}/VPSLabCloud/VPSLab-Free-Proxy-List/main/http_all.txt"},
    {"name": "vpslab/https",      "kind": "text", "scheme": "https",
     "url": f"{GH}/VPSLabCloud/VPSLab-Free-Proxy-List/main/http_ssl.txt"},
    {"name": "vpslab/socks4",     "kind": "text", "scheme": "socks4",
     "url": f"{GH}/VPSLabCloud/VPSLab-Free-Proxy-List/main/socks4_all.txt"},
    {"name": "vpslab/socks5",     "kind": "text", "scheme": "socks5",
     "url": f"{GH}/VPSLabCloud/VPSLab-Free-Proxy-List/main/socks5_all.txt"},
    # ---------- GitHub: MrMarble ----------
    {"name": "mrmarble/http",     "kind": "text", "scheme": "http",
     "url": f"{GH}/MrMarble/proxy-list/main/http_all.txt"},
    {"name": "mrmarble/https",    "kind": "text", "scheme": "https",
     "url": f"{GH}/MrMarble/proxy-list/main/http_ssl.txt"},
    {"name": "mrmarble/socks4",   "kind": "text", "scheme": "socks4",
     "url": f"{GH}/MrMarble/proxy-list/main/socks4_all.txt"},
    {"name": "mrmarble/socks5",   "kind": "text", "scheme": "socks5",
     "url": f"{GH}/MrMarble/proxy-list/main/socks5_all.txt"},
    # ---------- GitHub: proxio-io ----------
    {"name": "proxio/http",       "kind": "text", "scheme": "http",
     "url": f"{GH}/proxio-io/proxy-list/main/http.txt"},
    {"name": "proxio/https",      "kind": "text", "scheme": "https",
     "url": f"{GH}/proxio-io/proxy-list/main/https.txt"},
    {"name": "proxio/socks4",     "kind": "text", "scheme": "socks4",
     "url": f"{GH}/proxio-io/proxy-list/main/socks4.txt"},
    {"name": "proxio/socks5",     "kind": "text", "scheme": "socks5",
     "url": f"{GH}/proxio-io/proxy-list/main/socks5.txt"},
    # ---------- GitHub: proxmint ----------
    {"name": "proxmint/http",     "kind": "text", "scheme": "http",
     "url": f"{GH}/proxmint/free-proxy-list/main/http.txt"},
    {"name": "proxmint/https",    "kind": "text", "scheme": "https",
     "url": f"{GH}/proxmint/free-proxy-list/main/https.txt"},
    {"name": "proxmint/socks4",   "kind": "text", "scheme": "socks4",
     "url": f"{GH}/proxmint/free-proxy-list/main/socks4.txt"},
    {"name": "proxmint/socks5",   "kind": "text", "scheme": "socks5",
     "url": f"{GH}/proxmint/free-proxy-list/main/socks5.txt"},
    # ---------- GitHub: stormsia ----------
    {"name": "stormsia/http",     "kind": "text", "scheme": "http",
     "url": f"{GH}/stormsia/proxy-list/main/http.txt"},
    {"name": "stormsia/socks4",   "kind": "text", "scheme": "socks4",
     "url": f"{GH}/stormsia/proxy-list/main/socks4.txt"},
    {"name": "stormsia/socks5",   "kind": "text", "scheme": "socks5",
     "url": f"{GH}/stormsia/proxy-list/main/socks5.txt"},
    # ---------- GitHub: mixed-protocol lists ----------
    {"name": "themiralay/mixed",  "kind": "text", "scheme": "http",
     "url": f"{GH}/themiralay/Proxy-List-World/master/data.txt"},
    {"name": "hproxy/mixed",      "kind": "text", "scheme": "http",
     "url": f"{GH}/hproxy-com/free-proxy-list/main/all.txt"},
    {"name": "proxyscrape-gh/all", "kind": "json", "scheme": "http",
     "url": f"{GH}/ProxyScrape/free-proxy-list/main/proxies/all/data.json"},
    # ---------- API: openproxylist.xyz ----------
    {"name": "openproxy/http",    "kind": "text", "scheme": "http",
     "url": "https://api.openproxylist.xyz/http.txt"},
    {"name": "openproxy/https",   "kind": "text", "scheme": "https",
     "url": "https://api.openproxylist.xyz/https.txt"},
    {"name": "openproxy/socks4",  "kind": "text", "scheme": "socks4",
     "url": "https://api.openproxylist.xyz/socks4.txt"},
    {"name": "openproxy/socks5",  "kind": "text", "scheme": "socks5",
     "url": "https://api.openproxylist.xyz/socks5.txt"},
    # ---------- API endpoints ----------
    {"name": "proxyscrape/http",  "kind": "text", "scheme": "http",
     "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all"},
    {"name": "proxyscrape/https", "kind": "text", "scheme": "https",
     "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&timeout=10000&country=all"},
    {"name": "proxyscrape/socks4","kind": "text", "scheme": "socks4",
     "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks4&timeout=10000&country=all"},
    {"name": "proxyscrape/socks5","kind": "text", "scheme": "socks5",
     "url": "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all"},
    {"name": "proxyspace/http",   "kind": "text", "scheme": "http",
     "url": "https://proxyspace.pro/http.txt"},
    {"name": "proxyspace/https",  "kind": "text", "scheme": "https",
     "url": "https://proxyspace.pro/https.txt"},
    {"name": "proxyspace/socks5", "kind": "text", "scheme": "socks5",
     "url": "https://proxyspace.pro/socks5.txt"},
    {"name": "pubproxy",          "kind": "json", "scheme": "http",
     "url": "http://pubproxy.com/api/proxy?limit=20&format=json"},
    {"name": "geonode/page1",     "kind": "json", "scheme": "http",
     "url": "https://proxylist.geonode.com/api/proxy-list?limit=500&page=1&sort_by=lastChecked&sort_type=desc"},
    {"name": "geonode/page2",     "kind": "json", "scheme": "http",
     "url": "https://proxylist.geonode.com/api/proxy-list?limit=500&page=2&sort_by=lastChecked&sort_type=desc"},
    # ---------- HTML tables ----------
    {"name": "free-proxy-list.net", "kind": "html", "scheme": "http",
     "url": "https://free-proxy-list.net/"},
    {"name": "sslproxies.org",      "kind": "html", "scheme": "https",
     "url": "https://sslproxies.org/"},
    {"name": "us-proxy.org",        "kind": "html", "scheme": "http",
     "url": "https://www.us-proxy.org/"},
    {"name": "uk-proxy.org",        "kind": "html", "scheme": "http",
     "url": "https://uk-proxy.org/"},
    {"name": "socks-proxy.net",     "kind": "html", "scheme": "socks5",
     "url": "https://www.socks-proxy.net/"},
    {"name": "google-proxy.net",    "kind": "html", "scheme": "http",
     "url": "https://www.google-proxy.net/"},
    {"name": "freeproxy.world",     "kind": "freeproxy", "scheme": "http",
     "url": "http://www.freeproxy.world/?type=http&anonymity=&country=&speed=&port=&page=1"},
    # ---------- Plain-text pages ----------
    {"name": "spys.me",             "kind": "text", "scheme": "http",
     "url": "https://spys.me/proxy.txt"},
]

# ===========================================================================
# CHECK ENDPOINTS — rotated round-robin to spread the load
# ===========================================================================
CHECK_URLS = [
    "http://httpbin.org/ip",              # {"origin": "..."}
    "http://api.ipify.org/?format=json",  # {"ip": "..."}
    "http://checkip.amazonaws.com/",      # plain text ip
    "http://ipinfo.io/ip",                # plain text ip
    "http://whatismyip.akamai.com/",      # plain text ip (Akamai)
    "http://members.3322.org/dyndns/getip",  # plain text ip
]
# NOTE: no Cloudflare-fronted endpoints here (icanhazip etc.) — CF-edge IPs
# fake-pass those, then pollute the survivor set.

# Non-Cloudflare-fronted echo endpoints — used for VERIFICATION pass.
# Cloudflare-edge IPs fake-pass CF-fronted checkers (icanhazip) but fail these.
# 8 different services + retry-on-other-endpoint -> no single one gets hammered
# hard enough to rate-limit us (which would fake-fail good proxies).
VERIFY_URLS = [
    "http://checkip.amazonaws.com/",
    "http://whatismyip.akamai.com/",
    "http://ipinfo.io/ip",
    "http://api.ipify.org/?format=json",
    "http://httpbin.org/ip",
    "http://members.3322.org/dyndns/getip",
    "http://ipecho.net/plain",
    "http://ident.me/",
]

# Header-echo endpoints for ANONYMITY classification (tried in order, direct).
ANON_URLS = [
    "http://azenv.net/",
    "http://httpbin.org/get",
]

# Batch GEO enrichment (free tier: <=100 IPs per request, 45 req/min, http only)
GEO_URL = ("http://ip-api.com/batch?"
           "fields=status,message,country,countryCode,isp,org,as,proxy,hosting")

HEADERS = {
    "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                   "AppleWebKit/537.36 (KHTML, like Gecko) "
                   "Chrome/124.0 Safari/537.36"),
    "Accept": "*/*",
}

# ===========================================================================
# PARSING
# ===========================================================================
PAIR_RE = re.compile(
    r"(?:(?:https?|socks[45])://)?"
    r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\b"
)
HTML_PAIR_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s*</td>\s*<td[^>]*>\s*(\d{2,5})",
    re.IGNORECASE,
)
FREEPROXY_RE = re.compile(
    r"(\d{1,3}(?:\.\d{1,3}){3})\s*</td>\s*<td[^>]*>\s*"
    r"<a[^>]*href=\"/\?port=(\d{2,5})\"",
    re.IGNORECASE,
)

PROTO_KEYS = ("protocols", "protocol", "type", "scheme", "kind")
IP_KEYS = ("ip", "addr", "host", "server")
VALID_PROTOS = {"http", "https", "socks4", "socks5"}


def _valid_ip(ip: str) -> bool:
    return all(0 <= int(o) <= 255 for o in ip.split("."))


def _pairs_from(text):
    """Common (ip, port) extraction -> [(ip, port, None)]."""
    out = []
    for m in PAIR_RE.finditer(text):
        ip, port = m.group(1), int(m.group(2))
        if _valid_ip(ip) and 1 <= port <= 65535:
            out.append((ip, port, None))
    return out


def parse_text(text: str):
    return _pairs_from(text)


def parse_html(text: str):
    out = []
    for m in HTML_PAIR_RE.finditer(text):
        ip, port = m.group(1), int(m.group(2))
        if _valid_ip(ip) and 1 <= port <= 65535:
            out.append((ip, port, None))
    return out if out else _pairs_from(text)


def parse_freeproxy(text: str):
    out = []
    for m in FREEPROXY_RE.finditer(text):
        ip, port = m.group(1), int(m.group(2))
        if _valid_ip(ip) and 1 <= port <= 65535:
            out.append((ip, port, None))
    return out


def _norm_proto(p):
    p = str(p).strip().lower()
    if p in ("socks", "socks4/5", "socks5/4"):
        return "socks5"
    return p if p in VALID_PROTOS else None


def parse_json_any(text: str):
    """Walk ANY json; every dict with ip+port becomes a proxy entry.
    Per-entry protocol (protocols/protocol/type/...) overrides source tag."""
    out = []
    try:
        data = json.loads(text)
    except Exception:
        return out
    stack = [data]
    while stack and len(out) < 200000:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, dict):
            ip = None
            for k in IP_KEYS:
                v = node.get(k)
                if isinstance(v, str) and ":" in v:
                    # "addr": "1.2.3.4:8080"
                    host, _, p2 = v.rpartition(":")
                    if host and p2.isdigit():
                        ip, port = host, int(p2)
                        break
                if isinstance(v, str) and _valid_ip(v):
                    ip = v
                    break
            if ip is None:
                continue
            port = node.get("port")
            if not (isinstance(port, (int, str)) and str(port).isdigit()):
                continue
            port = int(port)
            if not (1 <= port <= 65535 and _valid_ip(ip)):
                continue
            protos = None
            for k in PROTO_KEYS:
                if k in node:
                    v = node[k]
                    if isinstance(v, str):
                        v = [v]
                    if isinstance(v, list):
                        protos = [_norm_proto(x) for x in v]
                        protos = [x for x in protos if x]
                    if protos:
                        break
            if protos:
                for p in protos:
                    out.append((ip, port, p))
            else:
                out.append((ip, port, None))
    return out


def parse_source(src, text: str):
    kind = src["kind"]
    if kind == "html":
        out = parse_html(text)
        if out:
            return out
        return _pairs_from(text)
    if kind == "freeproxy":
        return parse_freeproxy(text) or _pairs_from(text)
    if kind == "json":
        return parse_json_any(text) or _pairs_from(text)
    return parse_text(text)


# ===========================================================================
# STEP 1 — fetch all sources CONCURRENTLY
# ===========================================================================
async def fetch_one(session, src, retries=2):
    """Fetch one source; retry on failure (GitHub drops some of 90 parallel)."""
    for attempt in range(retries + 1):
        try:
            async with session.get(
                src["url"], headers=HEADERS,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as r:
                if r.status != 200:
                    if attempt < retries:
                        await asyncio.sleep(1.5 * (attempt + 1))
                        continue
                    return src, None
                return src, await r.text(errors="ignore")
        except Exception:
            if attempt < retries:
                await asyncio.sleep(1.5 * (attempt + 1))
                continue
            return src, None
    return src, None


async def fetch_all_sources(sources):
    print(f"[1/6] Fetching {len(sources)} sources in parallel...")
    connector = aiohttp.TCPConnector(limit=60, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        results = await asyncio.gather(*(fetch_one(session, s) for s in sources))
    ok = sum(1 for _, t in results if t is not None)
    print(f"      Fetched OK: {ok}/{len(sources)}")
    return results


# ===========================================================================
# STEP 2 — parse & deduplicate
# ===========================================================================
SCHEME_PRIORITY = {"socks5": 4, "socks4": 3, "https": 2, "http": 1}


def collect_proxies(fetched):
    print("[2/6] Parsing sources and deduplicating...")
    seen = {}  # ip:port -> proxy dict (first source wins, stronger scheme wins)
    order = []
    stats = []
    for src, text in fetched:
        if text is None:
            stats.append((src["name"], 0, 0))
            continue
        pairs = parse_source(src, text)
        new = 0
        for ip, port, proto in pairs:
            key = f"{ip}:{port}"
            scheme = proto if proto in SCHEME_PRIORITY else src["scheme"]
            if key in seen:
                # upgrade scheme if the new one is more specific
                existing = seen[key]
                if SCHEME_PRIORITY.get(scheme, 0) > \
                        SCHEME_PRIORITY.get(existing["scheme"], 0):
                    existing["scheme"] = scheme
                    existing["url"] = f"{scheme}://{ip}:{port}"
                continue
            entry = {
                "url": f"{scheme}://{ip}:{port}",
                "ip": ip, "port": port,
                "scheme": scheme,
                "src": src["name"],
            }
            seen[key] = entry
            order.append(entry)
            new += 1
        stats.append((src["name"], len(pairs), new))
    for name, total, new in stats:
        mark = "-" if total == 0 else "+"
        print(f"   {mark} {name:22} parsed={total:6}  new={new:6}")
    print(f"      TOTAL UNIQUE: {len(order)}")
    return order


# ===========================================================================
# STEP 3 — check every proxy
# ===========================================================================
def extract_origin(body: str):
    try:
        d = json.loads(body)
        for k in ("origin", "ip", "query"):
            if k in d:
                return d[k]
    except Exception:
        pass
    m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", body)
    return m.group(0) if m else "?"


async def check_http(session, proxy, check_url, timeout):
    start = time.perf_counter()
    async with session.get(
        check_url,
        proxy=f"http://{proxy['ip']}:{proxy['port']}",  # always http:// for aiohttp
        timeout=aiohttp.ClientTimeout(total=timeout),
        allow_redirects=False,
    ) as resp:
        latency = (time.perf_counter() - start) * 1000.0
        body = await resp.read()
        return resp.status == 200, latency, body.decode("utf-8", "ignore")


async def check_socks(proxy, check_url, timeout):
    start = time.perf_counter()
    connector = ProxyConnector.from_url(proxy["url"], rdns=True)
    async with aiohttp.ClientSession(connector=connector) as s:
        async with s.get(
            check_url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            allow_redirects=False,
        ) as resp:
            latency = (time.perf_counter() - start) * 1000.0
            body = await resp.read()
            return resp.status == 200, latency, body.decode("utf-8", "ignore")


async def get_direct_ip(session):
    """Our own egress IP (no proxy) — to drop transparent/fake proxies."""
    for url in VERIFY_URLS + CHECK_URLS:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as r:
                m = re.search(r"\d{1,3}(?:\.\d{1,3}){3}", await r.text())
                if m:
                    return m.group(0)
        except Exception:
            continue
    return None


async def pick_anon_url(session):
    """Find a working header-echo endpoint (direct, without proxy)."""
    for url in ANON_URLS:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=8)) as r:
                if r.status == 200:
                    body = await r.text()
                    if "REMOTE_ADDR" in body or "headers" in body:
                        print(f"      Anonymity endpoint: {url}")
                        return url
        except Exception:
            continue
    print("      WARNING: no anonymity endpoint reachable — anonymity skipped")
    return None


async def check_one(session, proxy, idx, timeout, max_latency_ms, sem,
                    check_urls=None, my_ip=None, retries=0):
    async with sem:
        start = time.perf_counter()
        urls = check_urls or CHECK_URLS
        for attempt in range(retries + 1):
            # rotate endpoint on retry so a rate-limited checker cannot
            # fake-fail a good proxy
            check_url = urls[(idx + attempt) % len(urls)]
            try:
                if proxy["scheme"].startswith("socks"):
                    ok, latency, body = await check_socks(proxy, check_url, timeout)
                else:
                    ok, latency, body = await check_http(session, proxy, check_url, timeout)
                if ok and latency < max_latency_ms:
                    echoed = extract_origin(body)
                    if my_ip and my_ip in echoed:
                        # echoes our own IP = transparent proxy or fake CF edge
                        return {**proxy, "ok": False, "latency_ms": latency}
                    return {**proxy, "ok": True,
                            "latency_ms": latency,
                            "echoed_ip": echoed}
            except Exception:
                pass
        return {**proxy, "ok": False,
                "latency_ms": (time.perf_counter() - start) * 1000.0}


async def check_all(proxies, concurrency, timeout, max_latency_ms, verbose=False,
                    check_urls=None, my_ip=None, tag="", retries=0):
    print(f"[3/6] Checking {len(proxies)} proxies{tag} "
          f"(concurrency={concurrency}, timeout={timeout}s, "
          f"max_latency={max_latency_ms}ms)...")
    if not SOCKS_SUPPORT:
        n_socks = sum(1 for p in proxies if p["scheme"].startswith("socks"))
        if n_socks:
            print(f"      WARNING: aiohttp-socks not installed — "
                  f"{n_socks} SOCKS proxies will be SKIPPED. "
                  f"Run: pip install aiohttp-socks")

    sem = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(limit=concurrency, force_close=True,
                                     ttl_dns_cache=600)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [
            asyncio.create_task(
                check_one(session, p, i, timeout, max_latency_ms, sem,
                          check_urls=check_urls, my_ip=my_ip, retries=retries)
            )
            for i, p in enumerate(proxies)
        ]
        results = []
        done, ok = 0, 0
        total = len(proxies)
        t0 = time.perf_counter()
        for fut in asyncio.as_completed(tasks):
            res = await fut
            results.append(res)
            done += 1
            if res.get("ok"):
                ok += 1
                if verbose:
                    print(f"   OK [{done}/{total}] {res['url']}  "
                          f"{res['latency_ms']:.0f}ms  "
                          f"(echo={res.get('echoed_ip', '?')})")
            if done % 1000 == 0:
                pps = done / max(time.perf_counter() - t0, 0.001)
                print(f"   .. [{done}/{total}] checked, {ok} working "
                      f"({pps:.0f} pps)")
    return results


# ===========================================================================
# QUALITY STAGE A — TLS CONNECT check (which proxies really work for https)
# ===========================================================================
async def connect_check_all(session, proxies, concurrency, timeout):
    print(f"[4/6] TLS CONNECT check on {len(proxies)} http(s) survivors...")
    sem = asyncio.Semaphore(min(concurrency, 500))

    async def one(p):
        async with sem:
            try:
                async with session.get(
                    "https://api.ipify.org/?format=json",
                    proxy=f"http://{p['ip']}:{p['port']}",
                    timeout=aiohttp.ClientTimeout(total=timeout + 2),
                    allow_redirects=False,
                ) as r:
                    await r.read()
                    return p["url"], r.status == 200
            except Exception:
                return p["url"], False

    out = {}
    done = 0
    for fut in asyncio.as_completed([one(p) for p in proxies]):
        u, okv = await fut
        out[u] = okv
        done += 1
        if done % 100 == 0:
            print(f"   .. [{done}/{len(proxies)}] connect-tested")
    return out


# ===========================================================================
# QUALITY STAGE B — anonymity: elite / anonymous / transparent
# ===========================================================================
LEAK_KEYS = ("http_x_forwarded_for", "http_client_ip", "http_x_real_ip",
             "http_forwarded", "x_forwarded_for", "client_ip", "x_real_ip",
             "forwarded")
VIA_KEYS = ("http_via", "http_x_forwarded_for", "http_forwarded",
            "http_client_ip", "http_proxy_connection", "via",
            "x_forwarded_for", "forwarded", "proxy_connection")


def parse_echo_headers(body: str):
    body = body.strip()
    try:
        d = json.loads(body)
        if isinstance(d, dict):
            hdrs = d.get("headers", d)
            if isinstance(hdrs, dict):
                return {str(k).lower().replace("-", "_"): str(v)
                        for k, v in hdrs.items()}
    except Exception:
        pass
    out = {}
    for line in body.splitlines():
        m = re.match(r"\s*([A-Za-z0-9_\-]+)\s*=\s*(.+?)\s*$", line)
        if m:
            out[m.group(1).lower().replace("-", "_")] = m.group(2)
    return out


def classify_anonymity(hdrs, my_ip):
    for k in LEAK_KEYS:
        v = hdrs.get(k)
        if v and my_ip and my_ip in v:
            return "transparent"     # BAD: leaks our real IP
    for k in VIA_KEYS:
        if hdrs.get(k):
            return "anonymous"       # hides IP, but proxy fact is visible
    return "elite"                   # hides both


async def anonymity_check_all(session, proxies, anon_url, my_ip,
                              concurrency, timeout):
    print(f"[5/6] Anonymity classification for {len(proxies)} survivors "
          f"(via {anon_url})...")
    sem = asyncio.Semaphore(min(concurrency, 300))

    async def one(p):
        async with sem:
            try:
                if p["scheme"].startswith("socks"):
                    connector = ProxyConnector.from_url(p["url"], rdns=True)
                    async with aiohttp.ClientSession(connector=connector) as s:
                        async with s.get(
                            anon_url,
                            timeout=aiohttp.ClientTimeout(total=timeout + 2),
                            allow_redirects=False,
                        ) as r:
                            body = await r.text(errors="ignore")
                else:
                    async with session.get(
                        anon_url,
                        proxy=f"http://{p['ip']}:{p['port']}",
                        timeout=aiohttp.ClientTimeout(total=timeout + 2),
                        allow_redirects=False,
                    ) as r:
                        body = await r.text(errors="ignore")
                hdrs = parse_echo_headers(body)
                return p["url"], classify_anonymity(hdrs, my_ip)
            except Exception:
                return p["url"], "unknown"

    out = {}
    done = 0
    for fut in asyncio.as_completed([one(p) for p in proxies]):
        u, level = await fut
        out[u] = level
        done += 1
        if done % 100 == 0:
            print(f"   .. [{done}/{len(proxies)}] classified")
    return out


# ===========================================================================
# QUALITY STAGE C — geo enrichment + "bad IP" flags (ip-api.com batch)
# ===========================================================================
async def geo_enrich(session, ips):
    print(f"[5b/6] Geo lookup for {len(ips)} unique IPs (ip-api.com batch)...")
    out = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            async with session.post(
                GEO_URL, json=chunk,
                timeout=aiohttp.ClientTimeout(total=15),
            ) as r:
                data = await r.json(content_type=None)
            if isinstance(data, list):
                for ip, item in zip(chunk, data):
                    if isinstance(item, dict) and item.get("status") == "success":
                        out[ip] = item
        except Exception:
            pass
        if i + 100 < len(ips):
            await asyncio.sleep(2.1)   # free tier: 45 req/min
        if (i // 100) % 5 == 0:
            print(f"   .. geo {i + len(chunk)}/{len(ips)}")
    print(f"      Geo resolved: {len(out)}/{len(ips)}")
    return out


# ===========================================================================
# STEP 6 — write output files
# ===========================================================================
def write_output(results, out_dir, max_latency_ms, csv_path=None):
    ok = [r for r in results if r.get("ok")]
    ok.sort(key=lambda r: r["latency_ms"])
    os.makedirs(out_dir, exist_ok=True)

    # buckets: https = really supports TLS CONNECT; http = plain http only
    buckets = {"http": [], "https": [], "socks4": [], "socks5": []}
    for r in ok:
        if r["scheme"].startswith("socks"):
            buckets[r["scheme"]].append(r)
        elif r.get("https_ok"):
            buckets["https"].append(r)
        else:
            buckets["http"].append(r)

    def dump(path, items):
        with open(path, "w", encoding="utf-8") as f:
            for r in items:
                f.write(r["url"] + "\n")

    dump(os.path.join(out_dir, "working_all.txt"), ok)
    for scheme, items in buckets.items():
        dump(os.path.join(out_dir, f"working_{scheme}.txt"), items)

    # elite subset (only when anonymity ran)
    if ok and any("anonymity" in r for r in ok):
        elite = [r for r in ok if r.get("anonymity") == "elite"]
        dump(os.path.join(out_dir, "working_elite.txt"), elite)

    # CSV with all quality columns
    if csv_path:
        import csv
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["url", "ip", "port", "scheme", "latency_ms",
                        "anonymity", "https_connect", "country", "country_code",
                        "isp", "as", "proxy_flag", "hosting_flag",
                        "source", "echoed_ip"])
            for r in ok:
                w.writerow([
                    r["url"], r["ip"], r["port"], r["scheme"],
                    f"{r['latency_ms']:.0f}",
                    r.get("anonymity", ""),
                    "yes" if r.get("https_ok") else "no",
                    r.get("country", ""), r.get("country_code", ""),
                    r.get("isp", ""), r.get("as", ""),
                    "yes" if r.get("proxy_flag") else "",
                    "yes" if r.get("hosting_flag") else "",
                    r["src"], r.get("echoed_ip", "?"),
                ])
        print(f"      CSV: {csv_path}")

    print(f"[6/6] Working proxies (<{max_latency_ms}ms): {len(ok)}")
    for scheme in ("http", "https", "socks4", "socks5"):
        print(f"      working_{scheme}.txt: {len(buckets[scheme])}")
    print(f"      working_all.txt:    {len(ok)}")
    print(f"      Saved to: {out_dir}")
    return ok


def print_quality_report(results):
    ok = [r for r in results if r.get("ok")]
    if not ok:
        return
    n = len(ok)
    anon = defaultdict(int)
    for r in ok:
        anon[r.get("anonymity", "unknown")] += 1
    conn_ok = sum(1 for r in ok if r.get("https_ok"))
    conn_no = sum(1 for r in ok if not r.get("https_ok")
                  and not r["scheme"].startswith("socks"))
    bad_flag = sum(1 for r in ok if r.get("proxy_flag"))
    hosting = sum(1 for r in ok if r.get("hosting_flag"))
    print("\n      " + "-" * 60)
    print("      QUALITY REPORT — which proxies are BAD:")
    if anon["transparent"]:
        print(f"      BAD  transparent : {anon['transparent']:4}  "
              f"(leak your real IP in X-Forwarded-For)")
    if anon["anonymous"]:
        print(f"      meh  anonymous   : {anon['anonymous']:4}  "
              f"(hide your IP but sites see a proxy is used)")
    if anon["elite"]:
        print(f"      GOOD elite       : {anon['elite']:4}  "
              f"(no Via/X-Forwarded-For headers — best choice)")
    if anon["unknown"]:
        print(f"      ?    unknown     : {anon['unknown']:4}  "
              f"(could not classify)")
    print(f"      TLS/HTTPS: {conn_ok} support CONNECT+TLS, "
          f"{conn_no} plain-http only")
    if bad_flag:
        print(f"      BAD  ip flagged  : {bad_flag:4}  "
              f"(IP already known in anti-fraud DBs -> often blocked)")
    if hosting:
        print(f"      meh  datacenter  : {hosting:4}  "
              f"(hosting/ISP IPs, not residential)")
    print("      -> working_elite.txt contains only GOOD elite proxies")
    print("      " + "-" * 60)


# ===========================================================================
# MAIN
# ===========================================================================
async def amain():
    ap = argparse.ArgumentParser(description="Multi-source proxy parser & checker")
    ap.add_argument("--out-dir", default=os.getcwd(),
                    help="Directory for output files")
    ap.add_argument("--timeout", type=float, default=4.0,
                    help="Per-proxy timeout, seconds")
    ap.add_argument("--concurrency", type=int, default=800,
                    help="Simultaneous checks (Windows-safe up to ~1000)")
    ap.add_argument("--max-latency", type=int, default=400,
                    help="Keep proxies with latency below this, ms")
    ap.add_argument("--limit", type=int, default=0,
                    help="Check only N random proxies (0 = all)")
    ap.add_argument("--only", default=None,
                    help="Comma-separated schemes to check, e.g. http,https")
    ap.add_argument("--no-html", action="store_true", help="Skip HTML sources")
    ap.add_argument("--no-socks", action="store_true", help="Skip SOCKS sources")
    ap.add_argument("--no-verify", action="store_true",
                    help="Skip verification pass (faster, more fakes)")
    ap.add_argument("--no-connect", action="store_true",
                    help="Skip TLS CONNECT capability check")
    ap.add_argument("--no-anonymity", action="store_true",
                    help="Skip elite/anonymous/transparent classification")
    ap.add_argument("--no-geo", action="store_true",
                    help="Skip ip-api country/proxy/hosting flags")
    ap.add_argument("--no-csv", action="store_true",
                    help="Do not write working_all.csv")
    ap.add_argument("--verbose", action="store_true",
                    help="Print every working proxy as found")
    ap.add_argument("--csv", default=None,
                    help="Custom CSV path (default: OUT_DIR/working_all.csv)")
    args = ap.parse_args()

    csv_path = args.csv or (None if args.no_csv else
                            os.path.join(args.out_dir, "working_all.csv"))

    t0 = time.perf_counter()
    print("=" * 70)
    print(" MULTI-SOURCE PROXY PARSER & CHECKER v2 (async, ~90 sources)")
    print("=" * 70)

    # -- 1. fetch --
    sources = SOURCES
    if args.no_html:
        sources = [s for s in sources if s["kind"] not in ("html", "freeproxy")]
    if args.no_socks:
        sources = [s for s in sources if not s["scheme"].startswith("socks")]
    fetched = await fetch_all_sources(sources)

    # -- 2. parse & dedupe --
    proxies = collect_proxies(fetched)
    if not proxies:
        print("No proxies found. Exiting.")
        sys.exit(1)

    # -- filter by scheme / limit --
    if args.only:
        allowed = {s.strip() for s in args.only.split(",")}
        proxies = [p for p in proxies if p["scheme"] in allowed]
        print(f"      Filtered by --only {allowed}: {len(proxies)} left")
    if args.limit and len(proxies) > args.limit:
        random.shuffle(proxies)
        proxies = proxies[:args.limit]
        print(f"      Random sample (--limit): {len(proxies)}")

    # -- direct IP + anonymity endpoint --
    connector = aiohttp.TCPConnector(limit=10, force_close=True)
    async with aiohttp.ClientSession(connector=connector) as s:
        my_ip = await get_direct_ip(s)
        print(f"      Direct egress IP: {my_ip}")
        anon_url = None if args.no_anonymity else await pick_anon_url(s)

    # -- 3. pass 1: fast discovery --
    results = await check_all(proxies, args.concurrency, args.timeout,
                              args.max_latency, verbose=args.verbose,
                              my_ip=my_ip)

    # -- 3b. pass 2: VERIFICATION (non-Cloudflare endpoints) --
    passed = [r for r in results if r.get("ok")]
    if passed and not args.no_verify:
        # shuffle so endpoint rotation is not correlated with pass-1 order
        random.shuffle(passed)
        print(f"[3b/6] Verifying {len(passed)} survivors "
              f"(non-Cloudflare endpoints, {len(VERIFY_URLS)} services)...")
        passed_proxies = [{k: v for k, v in r.items() if k in
                           ("url", "ip", "port", "scheme", "src")}
                          for r in passed]
        verified = await check_all(passed_proxies, min(args.concurrency, 600),
                                   args.timeout, args.max_latency,
                                   verbose=args.verbose,
                                   check_urls=VERIFY_URLS, my_ip=my_ip,
                                   retries=1)
        ok_urls = {r["url"] for r in verified if r.get("ok")}
        results = [r if (r.get("ok") and r["url"] in ok_urls)
                   else {**r, "ok": False} for r in results]
        dropped = len(passed) - len(ok_urls)
        print(f"      Verified: {len(ok_urls)}/{len(passed)} "
              f"({dropped} dropped as fake/flaky/unstable)")

    # -- 4. TLS CONNECT capability --
    survivors = [r for r in results if r.get("ok")]
    if survivors and not args.no_connect:
        fam = [r for r in survivors if not r["scheme"].startswith("socks")]
        if fam:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(
                    limit=500, force_close=True)) as conn_sess:
                conn_map = await connect_check_all(
                    conn_sess, fam, args.concurrency, args.timeout)
            for r in results:
                if r.get("ok") and r["url"] in conn_map:
                    r["https_ok"] = conn_map[r["url"]]
            print(f"      TLS CONNECT ok: "
                  f"{sum(1 for v in conn_map.values() if v)}/{len(fam)}")

    # -- 5. anonymity + geo --
    survivors = [r for r in results if r.get("ok")]
    if survivors and anon_url:
        anon_sess = aiohttp.ClientSession(connector=aiohttp.TCPConnector(
            limit=300, force_close=True))
        try:
            anon_map = await anonymity_check_all(
                anon_sess, survivors, anon_url, my_ip,
                args.concurrency, args.timeout)
        finally:
            await anon_sess.close()
        for r in results:
            if r.get("ok") and r["url"] in anon_map:
                r["anonymity"] = anon_map[r["url"]]

    survivors = [r for r in results if r.get("ok")]
    if survivors and not args.no_geo:
        unique_ips = list({r["ip"] for r in survivors})
        geo_sess = aiohttp.ClientSession(connector=aiohttp.TCPConnector(
            limit=5, force_close=True))
        try:
            geo_map = await geo_enrich(geo_sess, unique_ips)
        finally:
            await geo_sess.close()
        for r in results:
            g = geo_map.get(r.get("ip"))
            if r.get("ok") and g:
                r["country"] = g.get("country", "")
                r["country_code"] = g.get("countryCode", "")
                r["isp"] = g.get("isp", "")
                r["as"] = g.get("as", "")
                r["proxy_flag"] = bool(g.get("proxy"))
                r["hosting_flag"] = bool(g.get("hosting"))

    # -- 6. output --
    elapsed = time.perf_counter() - t0
    working = write_output(results, args.out_dir, args.max_latency,
                           csv_path=csv_path)

    # per-source stats
    src_ok = defaultdict(int)
    for r in results:
        if r.get("ok"):
            src_ok[r["src"]] += 1
    if src_ok:
        print("\n      Best sources:")
        for name, cnt in sorted(src_ok.items(), key=lambda kv: -kv[1])[:15]:
            print(f"        {name:22} {cnt:5} working")

    if working:
        print("\n      Top 15 fastest:")
        for i, r in enumerate(working[:15], 1):
            extra = ""
            if r.get("https_ok"):
                extra = " [TLS]"
            print(f"        {i:>3}  {r['url']:38} "
                  f"{r['latency_ms']:>7.0f}ms{extra}")

    print_quality_report(results)

    print("\n" + "=" * 70)
    print(f" DONE in {elapsed:.0f}s.  "
          f"{sum(1 for r in results if r.get('ok'))}/{len(results)} OK.")
    print(f" Output: {os.path.abspath(args.out_dir)}")
    print("=" * 70)


def _silence_proactor_noise(loop, context):
    """Windows/Proactor: swallow ConnectionResetError noise from
    _ProactorBasePipeTransport._call_connection_lost (known CPython quirk)."""
    exc = context.get("exception")
    if isinstance(exc, ConnectionResetError):
        return
    loop.default_exception_handler(context)


if __name__ == "__main__":
    # Linux/Mac: raise file-descriptor limit so high concurrency cannot
    # fail with 'Too many open files' (default is often just 1024).
    if sys.platform != "win32":
        try:
            import resource
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            resource.setrlimit(resource.RLIMIT_NOFILE,
                               (min(hard, 65535), hard))
        except Exception:
            pass

    if sys.platform == "win32":
        # Proactor handles high concurrency without FD_SETSIZE(512) limit;
        # its cosmetic ConnectionResetError noise is silenced above.
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

    # uvloop: 2-4x faster event loop on Linux/Mac (pip install uvloop)
    try:
        import uvloop
        uvloop.install()
    except ImportError:
        pass

    loop = asyncio.new_event_loop()
    loop.set_exception_handler(_silence_proactor_noise)
    try:
        loop.run_until_complete(amain())
    finally:
        loop.close()
