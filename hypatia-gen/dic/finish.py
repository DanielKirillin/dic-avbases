# -*- coding: utf-8 -*-
"""Завершение нашей сборки базы Hypatia (17.11.2026, Даниил: «если прямо все что в hypatia будет», «грузить только часть обновлённую»).

1. Список всех хэшей, собранных генератором (те же правила разбора, что в App.java), без исключений — all_hashes.txt.gz.
   Он копится от сборки к сборке (collect.sh подкладывает его как dic-previous.hashes), поэтому ничего не теряется.
2. Добавленное с прошлой сборки — hypatia-delta.txt.gz: программам хватит его вместо 40 МБ фильтров (дописать хэши в свой фильтр).
   Если исключения что-то убрали, дельтой это не передать — в описании full_required = true.
3. Фильтры MaintainTeam вливаются в наши побитово (те же размеры и число хэш-функций: App.java создаёт их с теми же параметрами).
   Итог — всё, что когда-либо было в Hypatia, плюс свежее. Проверка: ни одного бита их фильтра нет вне нашего.
4. manifest.json — версия, размеры и SHA-256 файлов, дельта, полнота, отчёт об источниках.
Запуск: finish.py <raw> <exclusions> <папка их фильтров> <прошлый all_hashes.txt.gz или -> <выход>
"""
import gzip, hashlib, json, os, re, sys, time

RAW, EXC, UP, PREV, OUT = sys.argv[1:6]
os.makedirs(OUT, exist_ok=True)
HEX = re.compile(r"^[0-9a-f]+$")
NAMES = ["hypatia-md5-bloom.bin", "hypatia-sha1-bloom.bin", "hypatia-sha256-bloom.bin", "hypatia-domains-bloom.bin"]


def ok(h):
    return len(h) in (32, 40, 64) and HEX.match(h) is not None


# ---------- исключения (как App.java: строчные, до первого «:», без «#») ----------
excl = set()
for f in sorted(os.listdir(EXC)) if os.path.isdir(EXC) else []:
    with open(os.path.join(EXC, f), encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip().lower().split(":")[0]
            if line and not line.startswith("#") and ok(line):
                excl.add(line)

# ---------- все хэши из raw (правила App.java) ----------
allh = set()
for f in sorted(os.listdir(RAW)):
    p = os.path.join(RAW, f)
    if not os.path.isfile(p) or f.endswith(".bin"):
        continue
    opener = gzip.open if f.endswith(".gz") else open
    name = f[:-3] if f.endswith(".gz") else f
    with opener(p, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip().lower()
            if name.endswith((".hdb", ".hsb", ".hdu", ".hsu")):
                if ":" not in line:
                    continue
                h = line.split(":")[0].strip()
            elif name.endswith(".loki"):
                if ";" not in line:
                    continue
                h = line.split(";")[0].strip()
            elif name.endswith((".md5", ".sha1", ".sha256", ".hashes", ".txt")):
                h = line
            else:
                continue
            if not h.startswith("#") and ok(h) and h not in excl:
                allh.add(h)

prev = set()
if PREV != "-" and os.path.isfile(PREV):
    with gzip.open(PREV, "rt", encoding="ascii", errors="replace") as fh:
        prev = {l.strip() for l in fh if l.strip()}
added = sorted(allh - prev)
removed = len(prev & excl)

with gzip.open(os.path.join(OUT, "all_hashes.txt.gz"), "wt", encoding="ascii", compresslevel=9) as fh:
    for h in sorted(allh):
        fh.write(h + "\n")
with gzip.open(os.path.join(OUT, "hypatia-delta.txt.gz"), "wt", encoding="ascii", compresslevel=9) as fh:
    for h in added:
        fh.write(h + "\n")
with open(os.path.join(OUT, "hypatia-exclusions.txt"), "w", encoding="ascii") as fh:
    fh.write("# Исключения DIC: хэши честных файлов, которые попадали в публичные списки. Применять и к чужой базе Hypatia.\n")
    for h in sorted(excl):
        fh.write(h + "\n")

# ---------- слить их фильтры в наши ----------
merge = {}
for n in NAMES:
    ours_p, theirs_p = os.path.join(RAW, n), os.path.join(UP, n)
    if not os.path.isfile(ours_p):
        merge[n] = "нашего фильтра нет"
        continue
    ours = bytearray(open(ours_p, "rb").read())
    if os.path.isfile(theirs_p):
        theirs = open(theirs_p, "rb").read()
        if theirs[:6] != ours[:6] or len(theirs) != len(ours):
            merge[n] = "параметры разные — не сливали"
        else:
            o = int.from_bytes(ours[6:], "big"); t = int.from_bytes(theirs[6:], "big")
            only_theirs = (t & ~o).bit_count()   # битов, которые есть только у них (их старые записи, которых уже нет в источниках)
            o |= t
            ours[6:] = o.to_bytes(len(ours) - 6, "big")
            if (t & ~o) != 0:
                merge[n] = "ОШИБКА: после слияния не всё"
            else:
                fill = o.bit_count() / ((len(ours) - 6) * 8)
                merge[n] = f"слито: их битов, которых не было у нас, {only_theirs}; заполнение {fill:.3f}"
    else:
        merge[n] = "их фильтра нет — только наш"
    open(os.path.join(OUT, n), "wb").write(ours)

# ---------- описание версии ----------
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


ver = time.strftime("%Y%m%d%H%M", time.gmtime())
prev_ver = None
pm = os.path.join(os.path.dirname(PREV), "manifest.json") if PREV != "-" else ""
if pm and os.path.isfile(pm):
    try:
        prev_ver = json.load(open(pm, encoding="utf-8")).get("version")
    except Exception:
        pass
files = {}
for n in NAMES + ["hypatia-delta.txt.gz", "hypatia-exclusions.txt"]:
    p = os.path.join(OUT, n)
    if os.path.isfile(p):
        files[n] = {"size": os.path.getsize(p), "sha256": sha(p)}
upgen = ""
if os.path.isfile(os.path.join(UP, "generation_time.html")):
    upgen = open(os.path.join(UP, "generation_time.html"), encoding="utf-8", errors="replace").read().strip()
manifest = {
    "format": 1,
    "version": ver,
    "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "files": files,
    "delta": {"from": prev_ver, "file": "hypatia-delta.txt.gz", "count": len(added)},
    "full_required": prev_ver is None or removed > 0,
    "hashes_total": len(allh),
    "excluded": len(excl),
    "upstream": {"generation_time": upgen, "merge": merge},
}
json.dump(manifest, open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
print(json.dumps(manifest, ensure_ascii=False, indent=1))
if any(v.startswith("ОШИБКА") for v in merge.values()):
    sys.exit(2)
