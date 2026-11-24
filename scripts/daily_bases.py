# DIC: daily phishing/malware domains -> phish_daily.bin.dicx (DICPH1, see DIC.LinkScan)
import gzip, hashlib, struct, sys, urllib.request

KEY = bytes([0x9E, 0xB7, 0xC5, 0xE3, 0xA9, 0xD1, 0xF2, 0x8B])
from noise_filter import noisy_drop, platform, popular

# (адрес, категория 1 фишинг / 2 вирусы, шумная): шумные ленты кладут целые площадки — их фильтр строже (scripts/noise_filter.py)
FEEDS = [
    ("https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt", 1, True),
    ("https://hole.cert.pl/domains/v2/domains.txt", 1, False),
    ("https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt", 1, False),
    ("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", 1, True),
    ("https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt", 2, False),
]
# Только подтверждает популярные сайты из шумных лент, в базу сама не идёт (курируемый список hagezi)
CONFIRM_ONLY = ["https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt"]


def host_of(line):
    s = line.strip().lower()
    if not s or s[0] in "#!":
        return None
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split(":", 1)[0].lstrip("*.").rstrip(".")
    if " " in s or "." not in s:
        return None
    return s


def own_sites(cats):
    """Our own list (dic_sites.txt in repo root): "domain category" per line, # comments; category 1 phishing, 2 malware."""
    try:
        lines = open("dic_sites.txt", encoding="utf-8").read().splitlines()
    except OSError as e:
        print("skip dic_sites.txt", e)
        return
    n = 0
    for line in lines:
        f = line.split("#", 1)[0].split()
        if not f:
            continue
        h = host_of(f[0])
        cat = int(f[1]) if len(f) > 1 and f[1].isdigit() else 2
        if not h:
            continue
        k = struct.unpack(">Q", hashlib.sha256(h.encode()).digest()[:8])[0]
        cats[k] = min(cats.get(k, cat), cat)
        n += 1
    print("dic_sites.txt", n)


def fetch(url):
    try:
        data = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "DIC-avbases"}), timeout=120).read()
    except Exception as e:
        print("skip", url, e)
        return None
    return [h for h in map(host_of, data.decode("utf-8", "replace").splitlines()) if h]


def main(out):
    cats = {}
    own_sites(cats)
    feeds = [(url, cat, noisy, fetch(url)) for url, cat, noisy in FEEDS]
    confirmed = set()
    for _, _, noisy, hosts in feeds:
        if not noisy and hosts:
            confirmed.update(h[4:] if h.startswith("www.") else h for h in hosts)
    for url in CONFIRM_ONLY:
        confirmed.update(h[4:] if h.startswith("www.") else h for h in fetch(url) or [])
    top = popular()
    for url, cat, noisy, hosts in feeds:
        if hosts is None:
            continue
        n = dropped = 0
        for h in hosts:
            if (noisy_drop(h, top, confirmed) if noisy else platform(h)):
                dropped += 1
                continue
            k = struct.unpack(">Q", hashlib.sha256(h.encode()).digest()[:8])[0]
            cats[k] = min(cats.get(k, cat), cat)
            n += 1
        print(url, n, "отсеяно", dropped)
    keys = sorted(cats)
    blob = b"DICPH1" + struct.pack(">I", len(keys)) + b"".join(struct.pack(">Q", k) for k in keys) + bytes(cats[k] for k in keys)
    z = gzip.compress(blob, compresslevel=9, mtime=0)
    open(out, "wb").write(b"DICX" + bytes(b ^ KEY[i % 8] for i, b in enumerate(z)))
    print("total", len(keys))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "phish_daily.bin.dicx")
