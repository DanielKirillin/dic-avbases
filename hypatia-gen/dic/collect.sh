#!/usr/bin/env bash
# Сбор источников для нашей сборки базы Hypatia (17.11.2026, Даниил: «наш -> hypatia», «учитывать ограничения на такие загрузки»).
# Источники те же, что у MaintainTeam (upstream_generate_stable.yml), с поправками:
#  • ClamAV — из нашего же выпуска latest (зеркало clamav-mirror), а не с серверов Cisco: у них лимиты на скачивание;
#  • abuse.ch (MalwareBazaar, ThreatFox) — полная выгрузка раз в неделю (воскресенье или FULL=1), в остальные дни — свежее за 48 ч;
#  • всё накопленное за прошлые сборки приходит списком all_hashes (dic-previous.hashes) — источник может отвалиться или
#    «забыть» старые хэши (ThreatView отдаёт только свежие), а наша база их не теряет;
#  • упавший источник не роняет сборку: пишем в отчёт и идём дальше.
# Запуск: collect.sh <рабочая папка> <репозиторий owner/name>
set -u
W="$1"; REPO="$2"
RAW="$W/raw"; EXC="$W/exclusions"; VAR="$W/various"; DOM="$W/domains"
mkdir -p "$RAW" "$EXC" "$VAR" "$DOM"
REPORT="$W/collect_report.txt"; : > "$REPORT"
note() { echo "$*" | tee -a "$REPORT"; }
GEN="$(cd "$(dirname "$0")/.." && pwd)"
cp "$GEN"/static/* "$RAW/"
cp "$GEN"/exclusions/* "$EXC/" 2>/dev/null || true

# abuse.ch с 2025 г. отдаёт выгрузки только с бесплатным ключом (без него — 410/401). Ключ — секрет ABUSECH_KEY.
AB=()
[ -n "${ABUSECH_KEY:-}" ] && AB=(-H "Auth-Key: $ABUSECH_KEY")
FULL="${FULL:-0}"
[ "$(date -u +%u)" = "7" ] && FULL=1
note "полная выгрузка abuse.ch: $FULL"

# --- накопленное за прошлые сборки ---
if gh release download hypatia-dic -R "$REPO" -p all_hashes.txt.gz -D "$VAR" --clobber 2>/dev/null; then
  gunzip -c "$VAR/all_hashes.txt.gz" > "$RAW/dic-previous.hashes"
  note "накоплено прежде: $(wc -l < "$RAW/dic-previous.hashes") хэшей"
else
  note "накопленного списка нет — первая сборка"
fi

# --- ClamAV (из нашего выпуска latest) ---
( set -e
  mkdir -p "$VAR/clam" && cd "$VAR/clam"
  gh release download latest -R "$REPO" -p main.cvd -p daily.cvd --clobber
  sigtool -u main.cvd && sigtool -u daily.cvd
  mv ./*.fp* "$EXC/" 2>/dev/null || true
  for e in hsb hdb hdu hsu; do ls ./*.$e >/dev/null 2>&1 && mv ./*.$e "$RAW/"; done
  true ) && note "ClamAV: ок" || note "ClamAV: НЕ ПОЛУЧИЛОСЬ"

# --- ESET ---
( set -e
  git clone -q --depth 1 https://github.com/eset/malware-ioc "$VAR/eset-sources"
  for t in md5 sha1 sha256; do
    find "$VAR/eset-sources" -maxdepth 2 -mindepth 1 -type f -name "samples.$t" -exec cat {} + | tr -d '\r' > "$RAW/eset.$t"
  done ) && note "ESET: ок" || note "ESET: НЕ ПОЛУЧИЛОСЬ"

# --- Signature-Base ---
curl -fsSL --retry 3 -o "$RAW/signature-base.loki" https://raw.githubusercontent.com/Neo23x0/signature-base/refs/heads/master/iocs/hash-iocs.txt \
  && note "Signature-Base: ок" || note "Signature-Base: НЕ ПОЛУЧИЛОСЬ"

# --- ThreatView (отдаёт свежие — старое держит накопленный список) ---
( set -e
  curl -fsSL --retry 3 https://threatview.io/Downloads/MD5-HASH-ALL.txt | sed 's/MD5 of //' | sort -u > "$RAW/threatview.md5"
  curl -fsSL --retry 3 https://threatview.io/Downloads/SHA-HASH-FEED.txt | sort -u > "$RAW/threatview.sha1" ) \
  && note "ThreatView: ок" || note "ThreatView: НЕ ПОЛУЧИЛОСЬ"

# --- ThreatFox (abuse.ch) ---
( set -e
  if [ "$FULL" = "1" ]; then
    curl -fsSL --retry 3 "${AB[@]}" -o "$VAR/threatfox.zip" "https://threatfox.abuse.ch/export/csv/sha256/full/"
    unzip -o -q "$VAR/threatfox.zip" -d "$VAR/threatfox"
    F=$(ls "$VAR"/threatfox/*.csv | head -1)
  else
    curl -fsSL --retry 3 "${AB[@]}" -o "$VAR/threatfox_recent.csv" "https://threatfox.abuse.ch/export/csv/sha256/recent/"
    F="$VAR/threatfox_recent.csv"
  fi
  # в CSV колонки разделены «", "» — берём сами 64-значные хэши, так не зависим от разделителей
  grep -v '^#' "$F" | grep -oE '[0-9a-fA-F]{64}' | sort -u > "$RAW/threatfox.sha256"
  [ -s "$RAW/threatfox.sha256" ] ) && note "ThreatFox: ок ($(wc -l < "$RAW/threatfox.sha256"))" || note "ThreatFox: НЕ ПОЛУЧИЛОСЬ"

# --- MalwareBazaar (abuse.ch) ---
( set -e
  if [ "$FULL" = "1" ]; then
    curl -fsSL --retry 3 "${AB[@]}" -o "$VAR/bazaar.zip" "https://bazaar.abuse.ch/export/txt/sha256/full/"
    unzip -o -q "$VAR/bazaar.zip" -d "$VAR/bazaar"
    cat "$VAR"/bazaar/*.txt
  else
    curl -fsSL --retry 3 "${AB[@]}" "https://bazaar.abuse.ch/export/txt/sha256/recent/"
  fi | tr -d '\r' | grep -oE '^[0-9a-fA-F]{64}' > "$RAW/malware_bazaar.sha256"
  [ -s "$RAW/malware_bazaar.sha256" ] ) && note "MalwareBazaar: ок ($(wc -l < "$RAW/malware_bazaar.sha256"))" || note "MalwareBazaar: НЕ ПОЛУЧИЛОСЬ"

# --- Stalkerware ---
( set -e
  curl -fsSL --retry 3 -o "$VAR/stalkerware.csv" https://raw.githubusercontent.com/AssoEchap/stalkerware-indicators/refs/heads/master/samples.csv
  tail -n +2 "$VAR/stalkerware.csv" | awk -F, '$1!="" && $5!="" {print $1":0:"$5}' > "$RAW/stalkerware.hsb" ) \
  && note "Stalkerware: ок" || note "Stalkerware: НЕ ПОЛУЧИЛОСЬ"

# --- SaneSecurity (rsync, раз в сутки — в пределах их правил) ---
( set -e
  mkdir -p "$VAR/sanesecurity" && cd "$VAR/sanesecurity"
  # без -a: права «только чтение» с сервера не переносим, иначе rsync сам не может писать в папку (первый прогон 17.11)
  rsync -rt --no-perms --chmod=ugo=rwX --timeout=120 rsync://rsync.sanesecurity.net/sanesecurity .
  for f in *.hsb *.hdb; do [ -f "$f" ] && sort -u "$f" > "$RAW/sanesecurity-$f"; done
  rm -f "$RAW/sanesecurity-crdfam.clamav.hdb" "$RAW/sanesecurity-doppelstern.hdb" "$RAW/sanesecurity-malware.expert.hdb"
  true ) && note "SaneSecurity: ок" || note "SaneSecurity: НЕ ПОЛУЧИЛОСЬ"

# --- Avast Covid-19 (Android) ---
( set -e
  git clone -q --depth 1 https://github.com/avast/covid-19-ioc.git "$VAR/covid"
  tail -q -n +2 "$VAR"/covid/datasets/android/*.csv | cut -d, -f1 | tr -d ' "' | sort -u > "$RAW/avast-covid19.sha256" ) \
  && note "Avast Covid-19: ок" || note "Avast Covid-19: НЕ ПОЛУЧИЛОСЬ"

# --- Targeted Threats ---
( set -e
  git clone -q --depth 1 https://github.com/botherder/targetedthreats.git "$VAR/targeted"
  tail -n +2 "$VAR/targeted/samples.csv" | tr -d '"' | awk -F, '{d=$4; if(d=="") d=$3; if(d=="") d="targetedthreats";
      if($1!="") print $1":0:"d > "'"$RAW"'/targetedthreats.hdb"; if($2!="") print $2":0:"d > "'"$RAW"'/targetedthreats.hsb"}' ) \
  && note "Targeted Threats: ок" || note "Targeted Threats: НЕ ПОЛУЧИЛОСЬ"

# --- Домены (Divested) ---
# 17.11 divested.dev отвечает 403 и с GitHub, и из России — тогда домены приходят из последней базы MaintainTeam (слияние)
curl -fsSL --retry 3 -A "Wget/1.21.4" -L -o "$DOM/divested.txt" "http://divested.dev/hosts-domains" \
  && note "Домены Divested: ок ($(wc -l < "$DOM/divested.txt"))" || note "Домены Divested: НЕ ПОЛУЧИЛОСЬ"

note "файлов в raw: $(ls "$RAW" | wc -l), исключений: $(cat "$EXC"/* 2>/dev/null | wc -l) строк"
exit 0
