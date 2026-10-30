#python parserik.py --only http,https --concurrency 800 --max-latency 400
#python parserik.py --only http,https --concurrency 800 --timeout 4 --max-latency 400
#python parserik.py --only http,https --no-html --no-anonymity --no-geo --no-connect



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

    


REQUIRES:
    pip install aiohttp aiohttp-socks
"""
