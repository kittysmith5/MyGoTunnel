#!/usr/bin/env bash
# Build only committed source, including when the working tree contains binaries.
set -euo pipefail
version=${1:?usage: release.sh VERSION OUTPUT_DIRECTORY SIGNING_KEY}
signing_key=$(realpath "${3:?signing key required}")
[[ -f "$signing_key" && $(stat -c %a "$signing_key") == 600 ]] || { echo "signing key must be a regular mode-0600 file" >&2; exit 1; }
public_key="${signing_key%.pem}.pub.pem"
[[ -f "$public_key" ]] || { echo "matching public key $public_key is required" >&2; exit 1; }
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
cp scripts/sync_certificate.py "$out/mygotunnel-cert-sync"
cp "$public_key" "$out/release-ed25519.pub.pem"
python3 - "$out" "$version" "$commit" "$built" "$signing_key" <<'PY'
import base64,hashlib,json,pathlib,subprocess,sys,tempfile
out=pathlib.Path(sys.argv[1]); key=pathlib.Path(sys.argv[5])
files={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.name in ['server-linux-arm64','server-linux-amd64','client-linux-arm64','client-linux-amd64','mygotunnelctl','observe.py','mygotunnel-cert-sync','release-ed25519.pub.pem']}
with tempfile.TemporaryDirectory() as d:
 pub=pathlib.Path(d)/'pub.der'; subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-outform','DER','-out',str(pub)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 keyid=hashlib.sha256(pub.read_bytes()[-32:]).hexdigest()[:16]
 manifest=dict(version=sys.argv[2],commit=sys.argv[3],built=sys.argv[4],key_id=keyid,files=files)
 payload=json.dumps(manifest,sort_keys=True,separators=(',',':')).encode(); pin=pathlib.Path(d)/'payload';sig=pathlib.Path(d)/'signature';pin.write_bytes(payload)
 subprocess.run(['openssl','pkeyutl','-sign','-inkey',str(key),'-rawin','-in',str(pin),'-out',str(sig)],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 manifest['signature']=base64.b64encode(sig.read_bytes()).decode()
 (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
PY
