# -*- coding: utf-8 -*-
"""Копии сторонних списков для телефонов в зеркале Яндекса (ext/), 17.11.2026.
Даниил: «все? с наших серваков и старые способы как резервные?» — телефоны берут сначала
https://storage.yandexcloud.net/dic-avbases/ext/<имя>, при 404 — прежние адреса.
Кладём файл, только если он скачался целиком и похож на список (не HTML-страница ошибки, не пустой, не обрезанный).
Не прошёл проверку — файла в out/ext нет, и в зеркале остаётся прежняя копия (rclone copy без удаления).
Запуск: ext_lists.py <папка out/ext>
"""
import os, sys, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from noise_filter import noisy_drop, norm, popular

NOISY = ("phishing-domains-ACTIVE.txt",)

OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
# (адрес, имя в ext/, минимум строк, лицензия/условия)
LISTS = [
    (["https://curbengh.github.io/phishing-filter/phishing-filter-domains.txt",
      "https://malware-filter.gitlab.io/phishing-filter/phishing-filter-domains.txt"],
     "phishing-filter-domains.txt", 1000, "malware-filter / phishing-filter (curbengh) — CC0 / MIT, данные OpenPhish, IPThreat, PhishTank"),
    (["https://hole.cert.pl/domains/v2/domains.txt"], "domains.txt", 1000, "CERT Polska, Lista ostrzeżeń — открытые данные CERT Polska"),
    (["https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains-online.txt",
      "https://curbengh.github.io/malware-filter/urlhaus-filter-domains-online.txt"],
     "urlhaus-filter-domains-online.txt", 100, "malware-filter / urlhaus-filter (curbengh) — CC0 / MIT, данные URLhaus (abuse.ch, CC0)"),
    (["https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"],
     "phishing-domains-ACTIVE.txt", 1000, "Phishing.Database (mitchellkrogza) — MIT"),
    (["https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt"],
     "tif.medium-onlydomains.txt", 1000, "hagezi/dns-blocklists — GPL-3.0"),
    (["https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/master/ioc.yaml"],
     "ioc.yaml", 50, "AssoEchap/stalkerware-indicators — CC BY 4.0"),
    # 17.11 Даниил: «пофиг на лицензию, бери» (phishing.army — CC BY-NC 4.0; риск по некоммерческой лицензии принят владельцем)
    (["https://phishing.army/download/phishing_army_blocklist_extended.txt"],
     "phishing_army_blocklist_extended.txt", 1000, "Phishing Army — CC BY-NC 4.0 (решение владельца DIC 17.11.2026)"),
    (["https://phishing.army/download/phishing_army_blocklist.txt"],
     "phishing_army_blocklist.txt", 1000, "Phishing Army — CC BY-NC 4.0 (решение владельца DIC 17.11.2026)"),
]

ok = []
got = {}
for urls, name, min_lines, lic in LISTS:
    data = None
    for u in urls:
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "DIC-mirror/1.0"})
            with urllib.request.urlopen(req, timeout=120) as r:
                ctype = r.headers.get("Content-Type", "")
                length = r.headers.get("Content-Length")
                b = r.read()
            if length and int(length) != len(b):
                print(f"{name}: {u} — обрезан ({len(b)} из {length})"); continue
            head = b[:512].lstrip().lower()
            if "html" in ctype.lower() or head.startswith(b"<!doctype") or head.startswith(b"<html"):
                print(f"{name}: {u} — пришла HTML-страница, не список"); continue
            text = b.decode("utf-8", "replace")
            lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith(("#", "!"))]
            if len(lines) < min_lines:
                print(f"{name}: {u} — мало строк ({len(lines)}), похоже на ошибку"); continue
            data = b
            print(f"{name}: ок, {len(b)} байт, строк {len(lines)} ({u})")
            break
        except Exception as e:
            print(f"{name}: {u} — {e}")
    if data is not None:
        got[name] = data
        ok.append((name, urls[0], lic))
    else:
        print(f"{name}: НЕ ОБНОВЛЁН — в зеркале остаётся прежняя копия")

# 24.11 Phishing.Database кладёт целые площадки (storage.yandexcloud.net — наш же сервер баз, away.vk.com, bit.ly…):
# в копии на зеркале их нет, правила те же, что у M-Базы (noise_filter.py). Подтверждают курируемые списки выше.
confirmed = set()
for n in ("phishing-filter-domains.txt", "domains.txt", "urlhaus-filter-domains-online.txt", "tif.medium-onlydomains.txt"):
    for l in got.get(n, b"").decode("utf-8", "replace").splitlines():
        l = l.strip().lower()
        if l and l[0] not in "#!":
            confirmed.add(norm(l.split("://", 1)[-1].split("/", 1)[0].lstrip("*.")))
top = popular()
for n in NOISY:
    if n in got:
        keep, drop = [], 0
        for l in got[n].decode("utf-8", "replace").splitlines():
            h = l.strip().lower()
            if h and h[0] not in "#!" and noisy_drop(h, top, confirmed):
                drop += 1
                continue
            keep.append(l)
        got[n] = ("\n".join(keep) + "\n").encode("utf-8")
        print(f"{n}: отсеяно {drop} площадок и популярных сайтов")
for name, data in got.items():
    open(os.path.join(OUT, name), "wb").write(data)

with open(os.path.join(OUT, "SOURCES.txt"), "w", encoding="utf-8") as f:
    f.write("Копии сторонних списков для DIC.Антивирус (обновляются раз в сутки). Источник и условия каждого:\n\n")
    for _, urls, name, _, lic in [(None,) + x for x in LISTS]:
        f.write(f"{name}\n  источник: {urls[0]}\n  условия: {lic}\n\n")
print(f"обновлено {len(ok)} из {len(LISTS)}")
