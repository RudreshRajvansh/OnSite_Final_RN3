# MaskedRunner — full architecture and rationale

Service-account workflow integrity verification.

This document explains what the system does, why it is built the way it is, the
real-world problem it addresses, every component, how data flows, what edge
cases it handles, and where its honest limits are.

---

## 1. The one idea

Every existing defence in this space asks one of two questions:

- **Who did this?** (identity, IAM, provenance)
- **Is this unusual?** (anomaly detection, behavioural baselines)

MaskedRunner asks a third question that neither of those can:

> **Was this outcome even possible?**

You declare the workflow once, as a formal model. For any run, MaskedRunner
tries to prove there is no legal execution of that model that produces what was
observed. If there isn't, the run is rejected, with the exact fact that made it
impossible.

**Rare is not the same as impossible. Everyone else checks rare.**

---

## 2. The real-world problem

### The attack surface

Almost every deployment now runs through a machine identity: a CI token, a
service account, an API key, and increasingly an AI agent credential. These
outnumber human accounts massively, and two structural properties make them
uniquely hard to defend:

1. **They bypass MFA by design.** There is no human to challenge.
2. **They have no meaningful behavioural baseline.** They run 24/7,
   deterministically, doing repetitive automated work. Anomaly detection has
   almost no signal to learn from, which is why "unusual" is the wrong question.

When one of these credentials is stolen, the attacker is not breaking in. They
are logged in, with a valid token. Every individual action they take is an
action that identity is permitted to perform. Nothing looks wrong.

### Incidents where every step was individually legitimate

- **@cap-js/cds-mtxs (18 May 2026)** — a malicious version published with a
  stolen npm token, bypassing the OIDC flow every legitimate release used.
  Nothing was unauthorised; the token was valid. What was wrong was structural:
  a publish with no producing CI run behind it.
- **keyv and family (4 Aug 2026)** and **@7nohe/openapi-react-query-codegen
  (28 Aug 2026)** — poisoned releases published to npm **with valid provenance
  signed by GitHub Actions**. 127M weekly downloads on the flagship package.
  Signed provenance answered "who built it" correctly and the attack still went
  through, because provenance attests to the builder's identity, not to whether
  the workflow that ran was legitimate.
- **TeamPCP (Mar 2026)** — a residual, incompletely rotated service-account
  token used to force-push across 110+ version tags. Every git operation was
  performed by an authorised identity.
- **TanStack (11 May 2026)** — a `pull_request_target` fork PR chained with
  Actions cache poisoning to extract OIDC tokens. The build ran normally; the
  inputs did not.

Every one of these is the same shape: valid credential, permitted actions,
ordinary sequence. That is the class MaskedRunner exists for, and the class that
identity checks, policy engines and anomaly models cannot separate from normal
work.

---

## 3. What MaskedRunner catches, in real-world terms

| Real situation | Verdict | Why |
|---|---|---|
| Stolen token publishes a package CI never built | REJECT | the publish effect has no producing transition |
| Poisoned build swapped in at publish | REJECT | published digest was not minted by any build |
| Attacker forges the provenance link | REJECT | the relation constraint `from.digest == to.digest` fails |
| Bot signs its own emergency approval | REJECT | identity not permitted for the approval transition |
| Stolen token reads a secret / publishes off-pipeline | REJECT | effect with no cause in the declared workflow |
| A job the workflow never declares appears | REJECT | unknown step |
| Same approval reused for a second publish | REJECT | the approval token was already consumed |
| Flaky test retried many times, then a real release | ACCEPT | retries are legal; the map has a loop |
| Emergency hotfix skips tests with human sign-off | ACCEPT | there is a legal break-glass path |
| Every job checks out (matrix / per-job checkout) | ACCEPT | concurrency is native to the model |
| Log lines dropped by the collector | ACCEPT under slack | missing logs are forgiven, missing causes are not |
| Three log sources with disagreeing clocks | no false reject | partial order, never one global timeline |

---

## 4. Why a coloured Petri net

The model has to express four things at once. The choice of model falls out of
that requirement.

| Requirement | Why it is needed |
|---|---|
| Concurrency without listing orderings | real pipelines fan out (matrix builds) and back in |
| Consumable resources | an approval is spent, not just checked; so is a lease or a slot |
| Loops | retries; without them the accepted set is finite and it is a whitelist |
| Data on the tokens | "the published digest must equal the one a build produced" |

Alternatives and where each one breaks:

- **Finite state machine / regex over step names.** One current position.
  Parallel jobs force you to enumerate interleavings by hand, so the spec
  becomes a list of allowed traces, the exact failure mode this is arguing
  against. No data, so a swapped digest is invisible.
- **A DAG (which `needs:` already is).** Acyclic, so no retries and a finite
  language. No resource semantics, so no replay protection. No data.
- **A plain (uncoloured) Petri net.** Gets concurrency, resources and loops
  right, but tokens are indistinguishable, so a swapped digest is undetectable.
  The single word "coloured" is what makes the core case work.
- **Datalog / Prolog over a provenance graph.** Reachability is natural, but it
  is monotone: facts only accumulate, nothing is ever spent, so consumption
  (the approval token) is awkward and needs negation plus time indices.
- **SMT (Z3).** Genuinely good and gives unsatisfiable cores for free, but you
  still have to encode the unfolding yourself, performance is unpredictable, and
  it is a heavy dependency for something that must run offline. Kept as the
  documented escalation path for arithmetic guards, not the default.

A coloured Petri net is the smallest model with all four properties. Drop the
colour and the digest attack is invisible; use a DAG and retries and the
approval token become inexpressible; use a state machine and the spec becomes
the whitelist the whole project rejects.

---

## 5. The formal decision

A workflow specification is a coloured workflow net with data-carrying tokens,
per-transition identity constraints, per-transition effect emission schemas,
relation schemas between effects, and global invariants.

An observation is a set of records drawn from multiple independent log planes
(CI runner, registry, cloud audit), treated as a **partial order**, not a
sequence.

The decision, `Verify(W, O)`:

> Does there exist an accepting firing sequence of the net, consistent with the
> observed steps and identities, whose emitted effect graph embeds the observed
> effect graph under a binding-preserving homomorphism?

- **Yes** → ACCEPT, and return the firing sequence as a witness path.
- **No** → REJECT, and return the minimal set of observed facts that no legal
  execution can produce, plus the specific obligation that failed.

Two properties, stated honestly:

- **Soundness relative to W.** Any rejection is a proof that no legitimate
  execution of the declared workflow produces the observation. No false
  positives with respect to the spec.
- **No claim beyond W.** If the spec is too permissive to exclude an attack,
  MaskedRunner accepts it, and the permissiveness meter reports exactly how
  permissive the spec is.

---

## 6. Architecture

```
crates/
  wsl/        spec parse, static soundness lint, mutation operators
  engine/     coloured net, bounded unfolding, unification, effect embedding
  explain/    minimal unsatisfiable subset, signed certificates
  adapters/   github | registry | cloud-audit normalizers
  api/        axum service: verify, live GitHub fetch, permission compare
  cli/        maskedrunner binary: verify, lint, generate, scenario, mutate
spec/         workflow specs + adapter maps
fixtures/     the three cases, held-out attacks, raw incident bundles
web/          the visualiser (net, ribbon, trace, why, certificate)
demo/         bot policy for the before/after scenario
.github/      the real release workflow
```

### Two verification layers

- **Layer 1, path feasibility.** Bounded unfolding of the net with guards,
  identity constraints, and binding unification. Answers: could these steps have
  fired, in some order, by these principals?
- **Layer 2, effect realizability.** The observed effect graph must embed into
  what the fired transitions could emit, with every declared relation obligation
  discharged against an effect a *preceding* transition produced. Answers: are
  the consequences producible?

A run can pass Layer 1 and fail Layer 2. That is exactly what happened at
cap-js: the steps looked fine, the effect had no cause.

### Why observations are a partial order

The run is stitched from three log sources with three clocks that disagree.
Sorting everything into one timeline (a total order) manufactures false
rejections from clock skew alone. Instead:

- timestamps order events **only within one source** (shared clock),
- causal edges order events **across sources** (cause precedes effect),
- everything else is left unordered, and the verifier accepts if **some** valid
  arrangement is legal.

This is a real correctness requirement, and few systems in this space handle it.

---

## 7. Data flow

### Offline verification (the core)

```
spec.wsl.yaml ──lint──> compiled net ─┐
                                       ├─> verify ─> ACCEPT + witness
observation.json ─────────────────────┘            or REJECT + minimal cause
                                                    └─> signed certificate
```

### Live GitHub verification (production shape)

```
browser: paste run URL
   │  fetch (public GitHub API, CORS-open; the verifier makes no outbound call)
   ▼
run.json + jobs.json
   │  POST /api/live
   ▼
server: adapter normalizes jobs -> observation
        auto-picks the matching spec
        runs BOTH checks:
          - legacy permission check (identity + scopes)  -> "without protection"
          - reachability verification                    -> "with protection"
   ▼
UI renders: ribbon, net, why, certificate, and the with/without comparison
```

The verifier never calls out to the network. The browser is the fetch client,
so "runs fully offline" stays true for the part that matters.

---

## 8. The auto-generator

`maskedrunner generate --workflow <file>` reads a real GitHub Actions workflow,
follows the `needs:` graph to build places and transitions, and infers each
job's effect from its name. On a simple pipeline it produces a spec that lints
sound with no edits; on a build/publish pipeline it inserts labelled TODOs where
a human must add the digest bindings and the `derives_from` link.

The honest position on prior art: deriving the job graph is standard (the
`needs:` graph is already a DAG; in-toto layouts already declare steps). What is
new is compiling it into a reachability model, and being explicit that the
security-critical part, the effect relations, still needs a human.

---

## 9. Certificates

Every verdict can be emitted as an Ed25519-signed, self-contained certificate:
spec hash, observation hash, bound, slack, robustness, the witness or the
minimal unsatisfiable set, and the failed obligations. It is re-verifiable by
someone who trusts neither the service nor its storage. Editing any field breaks
the payload hash before the signature is even checked.

This is what turns a verdict into evidence: admissible in incident response, a
compliance artifact, and attachable as an in-toto attestation.

---

## 10. Anti-allowlist evidence

The most likely criticism is "this is just a whitelist." Four answers, hardest
to argue with last:

1. **Infinite language.** `test` returns the artifact token, so retries are
   legal and the accepted set is infinite. A finite file cannot enumerate an
   infinite set. The permissiveness meter prints the growth: 2, 9, 29, 85, 233,
   610, 1552 distinct shapes by depth, still climbing.
2. **Legal-trace fuzzer.** 3977 random legal runs generated from the net, 511
   structurally distinct, all accepted, none written in the spec.
3. **Mutation testing.** No single spec clause removes the case-2 rejection; it
   takes exactly one pair out of 78, naming precisely which clauses are
   load-bearing.
4. **Held-out attacks.** Two attacks written after the engine was frozen, both
   caught with no code change.

---

## 11. What it does not claim

- **Soundness is relative to the spec.** A loose spec accepts more; the
  permissiveness meter measures how loose.
- **A compromised spec signing key** defeats it. Nothing below the root of trust
  helps.
- **Total suppression of every observation plane** defeats it. The assumption is
  that at least one plane is honest; which planes are trusted is declared, and
  any rejection depending on that assumption says so in the certificate.
- **Semantic malice in a legitimately built artifact** is out of scope. That is
  a scanner's job. MaskedRunner verifies the workflow could have produced the
  artifact, not that its contents are benign.

Known gaps, stated plainly: rollback of an old artifact rejects today (the
producing build is outside the observation window; the fix is to carry the
earlier certificate forward); cache poisoning is a data-integrity problem one
layer below reachability; anything inside a permitted transition's blast radius
is accepted by design and reported by the meter.

---

## 12. Future generalization

- **Near term:** more planes (CloudTrail, container registries) with the same
  engine. The model does not care what the workflow is, only that it is declared.
- **Any credentialed workflow with a declarable shape:** financial approval
  chains, healthcare order/verify/dispense, consent-gated data pipelines.
- **AI agent integrity, the strongest forward story.** Agents now hold
  credentials and chain tool calls autonomously. They have exactly the property
  that breaks every existing defence: no human to challenge, no stable baseline,
  every individual call permitted. Declare the agent's legitimate workflow, and
  every run is checked for reachability. This reframes MaskedRunner from a CI/CD
  tool into workflow integrity for autonomous systems.

---

## 13. Running it

```bash
cargo build --release            # build the engine, CLI and API
./demo.cmd                       # Windows: server + browser + CLI in one click
```

```bash
maskedrunner verify --observation fixtures/case2.json    # offline verify
maskedrunner scenario                                    # before/after contrast
maskedrunner generate --workflow .github/workflows/release.yml
maskedrunner lint --spec spec/release.wsl.yaml
```

The API serves the visualiser at http://localhost:8787. Paste a real GitHub
Actions run URL into the Live panel to fetch and verify it, then use
"Simulate a hijack" to see the contrast between the legacy permission check
(allows it) and MaskedRunner (rejects it).

18 tests: `cargo test --workspace`.
