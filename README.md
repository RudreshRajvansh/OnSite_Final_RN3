# MaskedRunner

Service-account workflow integrity verification.

Most defences in this space ask whether a behaviour is unusual. MaskedRunner asks whether an
outcome is possible. Only the second question survives an attacker who holds a valid credential
and follows the normal steps.

Rare is not the same as impossible. Everyone else checks rare.

When a run is rejected you get the smallest set of observed facts that no execution of the
declared workflow can produce, together with the obligation that failed. When a run is accepted
you get the legitimate path that explains it. There is no score anywhere in the output.

## What it does

You declare the workflow once, as a signed coloured Petri net: places, transitions, which
principal may fire what, which effects each transition may emit, and which relationships must hold
between those effects. The verifier then answers one question about a run assembled from
independent log planes.

> Does there exist an accepting firing sequence of the declared net, consistent with the observed
> steps and identities, whose emitted effect graph embeds the observed effect graph under a
> binding-preserving homomorphism?

No training data, no thresholds, no model, no confidence value. Nothing in `Cargo.toml` does
machine learning, and you can check that yourself in about ten seconds.

## Quickstart

```bash
cargo build --release
```

```bash
./target/release/maskedrunner lint
```

```bash
./target/release/maskedrunner verify --observation fixtures/case1.json
```

```bash
./target/release/maskedrunner-api
```

The service listens on `127.0.0.1:8787` and serves the visualiser from `web/`. Everything runs
offline. There are no CDN or network dependencies anywhere in the stack.

## The three cases

### 1. Legitimate

```
VERDICT   ACCEPT
WITNESS   checkout -> build -> test -> publish_standard
BOUND     k=4, slack=0
```

### 2. Malicious, same account, every step individually valid

The run looks like the normal run. Same service account, same four steps, same order, nothing
missing. Only the published digest is not the one the build minted.

```
VERDICT   REJECT  (robust: holds at maximum slack)
MINIMAL UNSATISFIABLE SET   (9 oracle calls)
  [1] registry_write(digest=sha256:BEEF, scope=registry://prod/app)
FAILED OBLIGATION
  transition `publish_standard` requires derives_from(e4 -> artifact_create)
  which the observation does not contain
  `publish_standard` emitted registry_write with digest=sha256:BEEF
  where the schema requires $digest = sha256:AA11
```

The core is a single fact. That one effect cannot be produced on its own, because no accepting
path of this workflow emits a `registry_write` without a `derives_from` edge to a build that
minted it. `robust` means the rejection survives unbounded assumed missing logging.

### 3. Unusual but permitted

No test ran. A human intervened mid-pipeline. A build was retried. This exact trace has never
occurred before in the pipeline's history.

```
VERDICT   ACCEPT
WITNESS   grant_emergency_approval -> checkout -> build -> build -> publish_breakglass
```

This is where behavioural detection fails and reachability does not. The map has a track for this
run, and the witness is that track. The approval token is consumed by the publish, so a second
publish on the same approval finds no token. There is a test for it rather than a claim about it.

## Real incidents

`fixtures/raw/` holds incidents as bundles of the three log planes. See
[docs/incidents.md](docs/incidents.md) for the mapping and the limits.

```bash
./target/release/maskedrunner ingest --bundle fixtures/raw/capjs.json --out /tmp/capjs.json
./target/release/maskedrunner verify --observation /tmp/capjs.json
```

```
VERDICT   REJECT  (robust: holds at maximum slack)
  [1] registry_write(digest=sha256:D00D, scope=registry://prod/app)
FAILED OBLIGATION
  registry_write `npm-77120.0` has no producing transition
```

The control run matters more than the detection. `fixtures/raw/capjs-provenance.json` is the same
run with genuine provenance for the build that actually happened. It rejects at `slack=0` but says
the rejection is explainable by unobserved steps, and it accepts at `--slack 1` with the publish
marked unobserved. A missing log line is forgiven; a missing causal link is not.

## This is not an allowlist

Four pieces of evidence, hardest to argue with last.

The accepted language is infinite. `test` returns the artifact token, so retry loops are legal and
unbounded, and a cyclic net cannot be an enumeration of allowed traces.

```
$ maskedrunner permissiveness --depth 11
DEPTH   DISTINCT EFFECT-GRAPH SHAPES
  4       2          8       233
  5       9          9       610
  6       29        10      1552
  7       85        11      2406+
LANGUAGE  infinite: the net contains a cycle, so no depth bounds the accepted set
```

The fuzzer generates random legal executions from the net, none of which appear anywhere in the
specification:

```
generated 3977 legal traces, 511 structurally distinct, all accepted
```

Mutation testing shows that the rejection is caused by named clauses rather than by an accident of
the implementation:

```
$ maskedrunner mutate --observation fixtures/case2.json
RESULT    0 of 13 single mutations remove the rejection
          the rejection is over-determined: 1 pair(s) of clauses must both be relaxed
MINIMAL RELAXATION
  drop-obligation:publish_standard/registry_write/derives_from
  loosen-arg:publish_standard/registry_write/digest
```

One pair out of 78 removes it: the effect obligation and the `$digest` binding, which are the two
halves of "the published digest must be one a preceding build minted".

Two more attacks were written after the engine was frozen. Both are caught with no engine changes.

| Fixture | Attack | Emitted counterexample |
|---|---|---|
| `attack-forged-provenance.json` | attacker fabricates the `derives_from` edge to launder a swapped digest | `edge derives_from(e4 -> e2) violates the declared constraint from.digest == to.digest` |
| `attack-self-approval.json` | service account issues its own break-glass approval, then publishes | ``grant_emergency_approval` was performed by `ci-bot@ci.internal` but the transition admits only `*@corp.example`` |

## Architecture

```
crates/
  wsl/        spec parse, static soundness lint, mutation operators
  engine/     coloured net, bounded unfolding, unification, effect-graph embedding
  explain/    minimal unsatisfiable subset, signed certificates
  adapters/   gh-actions | registry | cloud-audit normalizers
  api/        axum service, serves the visualiser
  cli/        maskedrunner binary
spec/         release.wsl.yaml, adapter.map.json
fixtures/     the three cases, held-out attacks, raw incident bundles
web/          net view, effect graph overlay, witness playback
```

Verification runs in two layers. Layer 1 checks path feasibility: bounded unfolding of the net
with guards, identity constraints and binding unification. Layer 2 checks effect realizability:
the observed effect graph must embed into what the fired transitions could have emitted, with
every declared relation obligation discharged against an effect that a preceding transition
produced. A run can pass layer 1 and still fail layer 2, which is what happened at cap-js.

Observations come from independent planes and are treated as a partial order rather than a
sequence. Timestamps order records only within a plane, and relation edges order them across
planes, so three log sources disagreeing about the clock cannot manufacture a rejection.

### Certificates

```bash
maskedrunner verify --observation fixtures/case2.json --certificate case2.cert.json
maskedrunner check --certificate case2.cert.json
```

The certificate is Ed25519-signed, self-contained, and re-verifiable by someone who trusts neither
the service nor its storage. It carries the spec hash, observation hash, bound, slack, robustness,
the minimal unsatisfiable set and the failed obligations. Editing any field breaks the payload hash
before the signature is even checked. Set `MASKEDRUNNER_SIGNING_KEY` to a 32-byte hex key, or an
ephemeral key is generated for you.

### Blocking a pipeline

`.github/workflows/_verify.yml` in the demo repo runs the verifier as a gate: it reads the run it
lives in from the Actions API, imports it, verifies it, and fails the workflow when the outcome is
unreachable. Wire it into any workflow with three lines:

```yaml
  maskedrunner:
    needs: [checkout, stamp, commit]
    if: always()
    uses: ./.github/workflows/_verify.yml
    with:
      run_id: ${{ github.run_id }}
      spec: maskedrunner/heartbeat.wsl.yaml
```

Anything integrating the CLI depends on its exit codes, so they are a contract:

| Code | Meaning |
|---|---|
| 0 | accepted: the observed run is reachable in the declared workflow |
| 1 | rejected: it is not, and the certificate says why |
| 2 | no verdict: the model, the map or the observation could not be read |

Two and one must never be collapsed. A gate that cannot read a run has not judged it, and showing
that as a rejection accuses a pipeline of something the verifier never concluded. The gate reports
each case separately, in the log and in the run summary.

## What it does not claim

Soundness is relative to the specification. A rejection proves that no execution of the declared
workflow produces the observation. If the spec is too permissive to exclude an attack, MaskedRunner
accepts it, and the permissiveness meter reports how permissive the spec is.

An adversary holding the spec signing key defeats it, because nothing below the root of trust
helps. Total suppression of every observation plane also defeats it. The assumption is that at
least one plane is honest. `planes[].complete` states which planes are trusted to be complete, and
any rejection that depends on that assumption says so in the certificate.

Semantic correctness of the artifact is out of scope. The verifier decides whether the workflow
could have produced the artifact, not whether the code inside it is benign.

Two implementation notes that differ from an idealised design, stated here because a reviewer will
find them anyway:

QuickXplain's complexity bound assumes monotonicity, and effect-relation facts break it. Adding a
`derives_from` edge can satisfy an obligation, so a superset can be satisfiable where a subset is
not. The extractor therefore runs a fixpoint deletion pass after QuickXplain to guarantee local
minimality instead of trusting the divide-and-conquer result.

The demo spec is sound but not free-choice, because `test` and `publish_standard` share the
`artifact` place with different preconditions. The general bounded procedure is used instead of the
polynomial free-choice one, and the linter says so rather than hiding it.

## Tests

```bash
cargo test --workspace
```

16 tests: spec lint, the three cases pinned with their exact witnesses, rejection robustness under
slack, single-use approval enforcement, the cap-js replay with its provenance control, the two
held-out attacks, and the legal-trace fuzzer.
