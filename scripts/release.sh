#!/usr/bin/env bash
# Build only committed source, including when the working tree contains binaries.
set -euo pipefail
version=${1:?usage: release.sh VERSION OUTPUT_DIRECTORY}
out=$(realpath -m "${2:?output directory required}")
commit=$(git rev-parse HEAD)
if ! git diff --quiet || ! git diff --cached --quiet; then
 echo 'Commit tracked changes before building a release' >&2; exit 1
fi
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git archive "$commit" | tar -x -C "$work"
built=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cd "$work"
for arch in arm64 amd64; do
 for role in server client; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false -ldflags "-X mygotunnel/internal/buildinfo.Version=$version -X mygotunnel/internal/buildinfo.Commit=$commit -X mygotunnel/internal/buildinfo.Built=$built" -o "$out/$role-linux-$arch" "./cmd/$role"
 done
done
cp scripts/mygotunnelctl.py "$out/mygotunnelctl"
cp scripts/observe.py "$out/observe.py"
python3 - "$out" "$version" "$commit" "$built" <<'PY'
import hashlib,json,pathlib,sys
out=pathlib.Path(sys.argv[1])
files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.name in ['server-linux-arm64','server-linux-amd64','client-linux-arm64','client-linux-amd64','mygotunnelctl','observe.py']}
(out/'manifest.json').write_text(json.dumps(dict(version=sys.argv[2],commit=sys.argv[3],built=sys.argv[4],files=files),indent=2)+'\n')
PY
