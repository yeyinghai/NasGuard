#!/bin/sh
# 打包 NasGuard 群晖套件：版本取自 CHANGELOG.md 最新一节，输出 dist/NasGuard-<版本>-0001.spk
set -e
cd "$(dirname "$0")"
V=$(sed -n 's/^## \([0-9][0-9.]*\) (.*/\1/p' CHANGELOG.md | head -1)
[ -n "$V" ] || { echo "CHANGELOG.md 里找不到版本号"; exit 1; }
grep -q "^VERSION = \"$V\"" NasGuard/src/app/guard.py || { echo "guard.py 里的 VERSION 与 CHANGELOG ($V) 不一致"; exit 1; }
B=$(mktemp -d); rm -rf dist; mkdir -p dist
chmod 755 NasGuard/src/bin/* NasGuard/src/ui/index.cgi NasGuard/pkg/scripts/*
tar --owner=0 --group=0 --exclude=__pycache__ -czf "$B/package.tgz" -C NasGuard/src app bin ui
SUM=$(md5sum "$B/package.tgz" | cut -d' ' -f1)
sed "s/@VERSION@/$V/" NasGuard/pkg/INFO.in > "$B/INFO"; echo "checksum=\"$SUM\"" >> "$B/INFO"
cp -r NasGuard/pkg/scripts NasGuard/pkg/conf NasGuard/pkg/PACKAGE_ICON.PNG NasGuard/pkg/PACKAGE_ICON_256.PNG "$B/"
SPK="NasGuard-$V-0001.spk"
tar --owner=0 --group=0 -cf "dist/$SPK" -C "$B" INFO package.tgz scripts conf PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG
rm -rf "$B"
python3 - "$V" "$SPK" <<'PY'
import sys, json, re
v, spk = sys.argv[1], sys.argv[2]
t = open('CHANGELOG.md', encoding='utf-8').read()
m = re.search(r'^## ' + re.escape(v) + r' \(([^)]*)\)\n(.*?)(?=^## |\Z)', t, re.S | re.M)
notes = m.group(2).strip()
json.dump({'version': v, 'date': m.group(1), 'spk': spk, 'notes': notes},
          open('version.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
open('dist/notes.md', 'w', encoding='utf-8').write(notes + '\n')
PY
echo "dist/$SPK"
