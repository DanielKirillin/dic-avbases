# База DIC (наша сборка Hypatia) — как устроено и как восстановить

С 17.11.2026 DIC собирает базу отпечатков вирусов сам. Раньше брали готовую у MaintainTeam (Hypatia), но их база
заброшена (последняя сборка 27.09.2026, «Maintained by: nobody»), и из неё нельзя убрать ложные записи
(у тестера системный `cmstp.exe` из Windows стал «вирусом»).

## Что в базе

- Те же открытые источники, что у Hypatia: ClamAV, ESET, MalwareBazaar, ThreatFox, ThreatView, SaneSecurity,
  Signature-Base, Stalkerware, Targeted Threats, Avast Covid-19, домены Divested.
- Тот же генератор (папка `src/`, версия MaintainTeam 3c35f52, лицензия GPL в `LICENSE`).
- Фильтры MaintainTeam вливаются в наши побитово (`dic/finish.py`): в нашей базе есть всё, что когда-либо было у них.
- Хэши копятся от сборки к сборке (`all_hashes.txt.gz` в выпуске) — источники могут «забывать» старое, мы нет.
- Исключения DIC (`exclusions/dic-exclusions.txt`) — честные файлы, попавшие в публичные списки. В нашу сборку не попадают;
  программы применяют этот же список и к чужой базе, когда берут её из резерва.

## Где лежит и в каком порядке берут программы

1. Яндекс: `https://storage.yandexcloud.net/dic-avbases/hypatia-dic/` (наша, основная)
2. GitHub: выпуск `hypatia-dic` в `DanielKirillin/dic-avbases` (наша, второй источник — из России медленный)
3. Резерв — база MaintainTeam: Яндекс `.../dic-avbases/hypatia/`, затем `https://maintainteam.github.io/HypatiaDatabases/`
   (подпись их ключом, `upstream_gpg.key`). Берётся, если нашей нет или она старше 3 суток (`manifest.json` → `date`).

Файлы: `hypatia-md5-bloom.bin`, `hypatia-sha1-bloom.bin`, `hypatia-sha256-bloom.bin`, `hypatia-domains-bloom.bin`
(формат Guava BloomFilter, как у Hypatia), `hypatia-delta.txt.gz` (хэши, добавленные с прошлой сборки),
`hypatia-exclusions.txt`, `manifest.json`. У каждого — подпись `.sig` (OpenPGP, ключ «DICPlay Hypatia Databases»,
отпечаток `A08D549DB91259D59964917FEEBF922553E8AEA5`).

## Обновление только изменённого

`manifest.json` → `delta.from` — версия, от которой посчитана дельта. Если у программы ровно эта версия и `full_required = false`,
ей достаточно скачать `hypatia-delta.txt.gz` (килобайты) и дописать хэши в свои фильтры (put в Guava BloomFilter по длине:
32 — md5, 40 — sha1, 64 — sha256). Иначе — полные фильтры.

## Ограничения источников

- ClamAV берём из нашего выпуска `latest` (его кладёт `clamav-mirror`), серверы Cisco не дёргаем.
- abuse.ch (MalwareBazaar, ThreatFox): полная выгрузка раз в неделю (воскресенье), в остальные дни — свежее за 48 часов.
- Остальные источники — раз в сутки. Упавший источник сборку не роняет: в `collect_report.txt` будет «НЕ ПОЛУЧИЛОСЬ»,
  накопленное остаётся.

## Ключи

- Закрытый: `C:\dic-tools\dic_hypatia_gpg_secret.asc` на ноутбуке, копия — Google Диск `DIC-архив/ключи/`,
  в GitHub — секрет `HYPATIA_GPG_KEY` репозитория dic-avbases.
- Открытый: `dic_hypatia_gpg_public.asc` (там же) — его встраивают в программы (ПК: `bases/`, телефоны — рядом с ключом Hypatia).

## Как пересобрать вручную (если GitHub недоступен)

Нужны Linux или WSL, Java 17, Maven, Python 3.10+, `sigtool` (пакет clamav), `gh`, `rsync`, `unzip`, `gpg`.

```bash
W=$PWD/work
bash hypatia-gen/dic/collect.sh "$W" DanielKirillin/dic-avbases
mkdir -p "$W/upstream" "$W/prev"
for f in hypatia-md5-bloom.bin hypatia-sha1-bloom.bin hypatia-sha256-bloom.bin hypatia-domains-bloom.bin generation_time.html; do
  curl -fsSL -o "$W/upstream/$f" "https://maintainteam.github.io/HypatiaDatabases/$f"; done
(cd hypatia-gen && mvn -q -B clean compile exec:java -Dexec.mainClass=org.maintainteam.hypatiadatabases.App -Dexec.args="$W/raw/ $W/domains/divested.txt")
python3 hypatia-gen/dic/finish.py "$W/raw" "$W/exclusions" "$W/upstream" - "$W/out"
gpg --import dic_hypatia_gpg_secret.asc
cd "$W/out" && for f in hypatia-*-bloom.bin hypatia-delta.txt.gz hypatia-exclusions.txt manifest.json; do gpg --detach-sign -o "$f.sig" "$f"; done
```

Готовые файлы из `$W/out` выложить в Яндекс (`hypatia-dic/`) и/или в выпуск `hypatia-dic`.
Если нет вообще ничего — последние копии базы лежат на Google Диске `DIC-архив/hypatia-dic/база/`.
