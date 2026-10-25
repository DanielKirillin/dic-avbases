# DIC: daily phishing/malware domains -> phish_daily.bin.dicx (DICPH1, see DIC.LinkScan)
import gzip, hashlib, struct, sys, urllib.request

KEY = bytes([0x9E, 0xB7, 0xC5, 0xE3, 0xA9, 0xD1, 0xF2, 0x8B])
FEEDS = [
    ("https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt", 1),
    ("https://hole.cert.pl/domains/v2/domains.txt", 1),
    ("https://malware-filter.gitlab.io/malware-filter/phishing-filter-domains.txt", 1),
    ("https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt", 1),
    ("https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt", 2),
]
SHARED = set("""sites.google.com bit.ly t.co goo.gl tinyurl.com 000webhostapp.com firebaseapp.com web.app github.io gitlab.io pages.dev
workers.dev vercel.app netlify.app glitch.me repl.co replit.dev herokuapp.com blogspot.com wordpress.com wixsite.com weebly.com tilda.ws
ucoz.ru narod.ru square.site webflow.io mystrikingly.com carrd.co linktr.ee forms.gle docs.google.com drive.google.com
storage.googleapis.com s3.amazonaws.com amazonaws.com cloudfront.net azurewebsites.net windows.net r2.dev ipfs.io dweb.link cutt.ly
clck.ru vk.cc t.me telegra.ph notion.site googleusercontent.com appspot.com firebaseio.com duckdns.org no-ip.org ddns.net is.gd
ow.ly rebrand.ly shorturl.at rb.gy surl.li qrco.de github.com raw.githubusercontent.com dropbox.com discord.com cdn.discordapp.com""".split())


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


def main(out):
    cats = {}
    for url, cat in FEEDS:
        try:
            data = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "DIC-avbases"}), timeout=120).read()
        except Exception as e:
            print("skip", url, e)
            continue
        n = 0
        for line in data.decode("utf-8", "replace").splitlines():
            h = host_of(line)
            if not h or h in SHARED:
                continue
            k = struct.unpack(">Q", hashlib.sha256(h.encode()).digest()[:8])[0]
            cats[k] = min(cats.get(k, cat), cat)
            n += 1
        print(url, n)
    keys = sorted(cats)
    blob = b"DICPH1" + struct.pack(">I", len(keys)) + b"".join(struct.pack(">Q", k) for k in keys) + bytes(cats[k] for k in keys)
    z = gzip.compress(blob, compresslevel=9, mtime=0)
    open(out, "wb").write(b"DICX" + bytes(b ^ KEY[i % 8] for i, b in enumerate(z)))
    print("total", len(keys))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "phish_daily.bin.dicx")
