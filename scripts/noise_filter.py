# -*- coding: utf-8 -*-
"""Отсев ложных записей из шумных лент фишинга (24.11.2026).

Phishing.Database (mitchellkrogza) и OpenPhish кладут в список целые площадки, где когда-то лежал фишинг:
storage.yandexcloud.net (наш сервер баз!), away.vk.com, l.instagram.com, docs.google.com, bit.ly, gravatar.com…
Блокировка по домену отключала такую площадку целиком. Разбор — сессия DIC.Антивирус, C:/gt_tmp/lb/ЛОЖНЫЕ_БЛОКИ_24.11.md.

Правила (те же, что в мобильных DIC 4.2.1, Р 1.5.1, Рубин 2.0, Доктор 2.1):
 1. SHARED — сама площадка (хостинг, хранилище, сокращатель, переходник соцсети) не блокируется. Конкретный сайт на ней
    (имя.github.io, корзина.storage.googleapis.com) — блокируется как раньше.
 2. BIG — домены, поддомены которых раздаёт только владелец: любые их записи в лентах ложные.
 3. Популярные сайты (Tranco top-50k) из шумных лент не берём, если их не подтверждает курируемая лента
    (CERT Polska, phishing-filter, URLhaus, hagezi tif). Список не скачался — правило пропускается, 1 и 2 работают.
 Поддомены популярных сайтов НЕ отсеиваем: проверено 24.11 — это 16 тыс. записей, почти все на хостингах для всех
 (godaddysites.com, blogspot.*, webcindario.com, tmweb.ru, бесплатные DNS) — настоящий фишинг.
Только стандартная библиотека Python.
"""
import csv, io, urllib.request, zipfile

SHARED = set("""sites.google.com bit.ly t.co goo.gl tinyurl.com 000webhostapp.com firebaseapp.com web.app github.io gitlab.io pages.dev
workers.dev vercel.app netlify.app glitch.me repl.co replit.dev herokuapp.com blogspot.com wordpress.com wixsite.com weebly.com tilda.ws
ucoz.ru narod.ru square.site webflow.io mystrikingly.com carrd.co linktr.ee forms.gle docs.google.com drive.google.com
storage.googleapis.com s3.amazonaws.com amazonaws.com cloudfront.net azurewebsites.net windows.net r2.dev ipfs.io dweb.link cutt.ly
clck.ru vk.cc t.me telegra.ph notion.site googleusercontent.com appspot.com firebaseio.com duckdns.org no-ip.org ddns.net is.gd
ow.ly rebrand.ly shorturl.at rb.gy surl.li qrco.de github.com raw.githubusercontent.com dropbox.com discord.com cdn.discordapp.com
storage.yandexcloud.net website.yandexcloud.net firebasestorage.googleapis.com storage.cloud.google.com s3.timeweb.cloud filesusr.com
u.to infura-ipfs.io cloudflare-ipfs.com arweave.net gravatar.com getpocket.com pastebin.com tilda.cc medium.com yandexcloud.net googleapis.com
away.vk.com l.instagram.com l.facebook.com lm.facebook.com out.reddit.com""".split())

BIG = set("""google.com youtube.com vk.com vk.ru mail.ru ok.ru instagram.com facebook.com archive.org yandex.ru yandex.net
apple.com microsoft.com gosuslugi.ru dicantivirus.ru ubisoft.com""".split())

TRANCO = "https://tranco-list.eu/top-1m.csv.zip"
TOP = 50000


def norm(h):
    return h[4:] if h.startswith("www.") else h


def platform(h):
    """Запись — сама площадка или поддомен крупного домена: в базу не берём."""
    h = norm(h)
    if h in SHARED:
        return True
    return any(h == b or h.endswith("." + b) for b in BIG)


def popular(zip_path=None):
    """Tranco top-50k (без www.); пустое множество, если список не скачался. zip_path — локальная копия top-1m.csv.zip."""
    try:
        if zip_path:
            data = open(zip_path, "rb").read()
        else:
            data = urllib.request.urlopen(urllib.request.Request(TRANCO, headers={"User-Agent": "DIC-avbases"}), timeout=120).read()
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            rows = csv.reader(io.TextIOWrapper(z.open(z.namelist()[0]), encoding="utf-8"))
            top = set()
            for r in rows:
                if int(r[0]) > TOP:
                    break
                top.add(norm(r[1].strip().lower()))
        print("tranco top", len(top))
        return top
    except Exception as e:
        print("tranco: не скачался, правило популярных пропущено:", e)
        return set()


def noisy_drop(h, top, confirmed):
    """Запись из шумной ленты не берём: площадка, крупный домен или популярный сайт без подтверждения."""
    h = norm(h)
    return platform(h) or (h in top and h not in confirmed)
