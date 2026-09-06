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
read -rp "  [enter] "

beat "5  The harder attack: forge your own certificate."
FORGED="${TMPDIR:-/tmp}/maskedrunner-forged.cert.json"
ATTACKER_RUN="${TMPDIR:-/tmp}/maskedrunner-attacker.json"
sed 's/sha256:AA11/sha256:DEAD/g; s/case1-legitimate/attacker-run/' fixtures/case1.json > "$ATTACKER_RUN"
echo "  The attacker runs a pipeline of their own for sha256:DEAD and signs"
echo "  the result with a key they generated. The signature is real."
echo
MASKEDRUNNER_SIGNING_KEY=abababababababababababababababababababababababababababababababab \
  "$BIN" verify --observation "$ATTACKER_RUN" --certificate "$FORGED" | head -2
echo
"$BIN" verify --observation fixtures/case5-rollback-forged.json --evidence "$FORGED"
echo
echo "  Refused, and note the exit code is 2, not 1: no verdict was reached."
echo "  A valid signature only proves the document was not edited. It says"
echo "  nothing about who wrote it, so the issuer has to be one we trust."
echo
