#!/usr/bin/env bash
# Резерв нашей базы Hypatia на Google Диск DICPlay (Даниил 17.11: «резерв на всякий просто для сохранения на гугл диск DICPlay
# с инструкцией и скриптами»). Запускается на ноутбуке (rclone с удалённым gdrive: = аккаунт DICPlay). Только copy, без удаления;
# RusMind-архив не трогаем.
#   gdrive:DIC-архив/hypatia-dic/база/последняя/   — свежая сборка с зеркала Яндекса (перезаписывается)
#   gdrive:DIC-архив/hypatia-dic/база/<ГГГГ-ММ>/   — снимок раз в месяц
#   gdrive:DIC-архив/hypatia-dic/генератор/        — hypatia-gen (код, исключения, инструкция) и задачи GitHub
#   gdrive:DIC-архив/ключи/                         — ключи подписи (закрытый и открытый)
set -euo pipefail
R="${RCLONE:-/e/dicbuild/rclone/rclone.exe}"
REPO="${REPO:-/e/dicbuild/dic-avbases}"
D="gdrive:DIC-архив/hypatia-dic"
# Генератор, инструкция, задачи GitHub и ключи — всегда (база может ещё не собраться, а восстановить её без них нельзя)
"$R" copy "$REPO/hypatia-gen" "$D/генератор/hypatia-gen" --checksum
"$R" copy "$REPO/.github/workflows" "$D/генератор/workflows" --checksum --include "hypatia-build.yml" --include "mirror-sync.yml" --include "clamav-mirror.yml"
"$R" copy "$REPO/hypatia-gen/README_DIC.md" "$D" --checksum
"$R" copy /c/dic-tools "gdrive:DIC-архив/ключи" --include "dic_hypatia_gpg_*.asc"
# База — с зеркала Яндекса, если она там уже есть
T="$(mktemp -d)"
B=https://storage.yandexcloud.net/dic-avbases/hypatia-dic
if ! curl -fsSL -o "$T/manifest.json" "$B/manifest.json"; then
  echo "базы на зеркале пока нет — сохранены генератор, инструкция и ключи"; rm -rf "$T"; exit 0
fi
for f in $(python -c "import json,sys;print(' '.join(json.load(open(sys.argv[1],encoding='utf-8'))['files']))" "$T/manifest.json") manifest.json; do
  curl -fsSL -o "$T/$f" "$B/$f"; curl -fsSL -o "$T/$f.sig" "$B/$f.sig" || true
done
"$R" copy "$T" "$D/база/последняя" --checksum
"$R" copy "$T" "$D/база/$(date +%Y-%m)" --checksum
"$R" check "$T" "$D/база/последняя" --one-way --checksum
echo "резерв на Google Диске обновлён: версия $(python -c "import json,sys;print(json.load(open(sys.argv[1],encoding='utf-8'))['version'])" "$T/manifest.json")"
rm -rf "$T"
