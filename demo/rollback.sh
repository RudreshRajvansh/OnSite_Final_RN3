#!/usr/bin/env bash
# The rollback demo. Four beats, in order:
#   1. a normal release, which issues a signed certificate
#   2. a rollback of that artifact weeks later, with nothing to show for it
#   3. the same rollback with the original certificate presented
#   4. a rollback of a digest nobody ever built, certificate and all
set -u
cd "$(dirname "$0")/.."

export MASKEDRUNNER_SIGNING_KEY=1111111111111111111111111111111111111111111111111111111111111111
BIN=target/release/maskedrunner
CERT="${TMPDIR:-/tmp}/maskedrunner-release.cert.json"

[ -x "$BIN" ] || cargo build --release -p maskedrunner-cli

beat() {
  echo
  echo "============================================================"
  echo "  $1"
  echo "============================================================"
}

beat "1  The original release, three weeks ago"
"$BIN" verify --observation fixtures/case1.json --certificate "$CERT"
read -rp "  [enter] "

beat "2  Production is broken. Roll back. No evidence presented."
"$BIN" verify --observation fixtures/case4-rollback.json
echo
echo "  Rejected. Nothing in THIS run built that digest, and the"
echo "  verifier will not take the runner's word for it."
read -rp "  [enter] "

beat "3  Same rollback. Now present the original certificate."
"$BIN" verify --observation fixtures/case4-rollback.json --evidence "$CERT"
echo
echo "  Accepted. The signature proves that digest already passed"
echo "  build and test under this same workflow."
read -rp "  [enter] "

beat "4  The attack: roll back a digest that never existed."
"$BIN" verify --observation fixtures/case5-rollback-forged.json --evidence "$CERT"
echo
echo "  Rejected. A certificate is evidence for the digest it names"
echo "  and nothing else. It is not a skip button."
echo
