#!/bin/bash
# Build pw-tuneup.exe for x64 and ARM64 into dist/win/<arch>/ with version.json and SHA256SUMS.
# Needs Go 1.24+; no cgo. 
#
#   ./build.sh          # both arches
#   ./build.sh arm64    # one
set -eu
cd "$(dirname "$0")"
export GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=windows
VER=$(sed -n 's/^const Version = "\([^"]*\)".*/\1/p' cmd/pw-tuneup/main.go)
[ -n "$VER" ] || { echo "no Version in cmd/pw-tuneup/main.go"; exit 1; }
go vet ./... >/dev/null
for arch in ${1:-amd64 arm64}; do
  out="dist/win/$arch"; mkdir -p "$out"
  GOARCH=$arch go build -trimpath -ldflags "-s -w" -o "$out/pw-tuneup.exe" ./cmd/pw-tuneup
  printf '{"kind":"exe","name":"pw-tuneup","ver":"%s","arch":"%s","built":"%s"}\n' "$VER" "$arch" "$(date -u +%FT%TZ)" > "$out/version.json"
  (cd "$out" && sha256sum pw-tuneup.exe > SHA256SUMS)
  echo "$arch: $VER  $(du -h "$out/pw-tuneup.exe" | cut -f1)"
done
