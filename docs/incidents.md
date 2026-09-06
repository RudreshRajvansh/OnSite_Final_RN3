# Incident mapping

What MaskedRunner would have emitted for real, dated supply-chain compromises, and where it would
have stayed silent.

Every incident below shares one property: the credential was valid and the individual actions were
authorised. That is the class this project exists for, and it is the class that step allowlists,
request-scoped policy engines and behavioural baselines cannot separate from normal work.

## Replayed in this repository

### @cap-js/cds-mtxs, 18 May 2026

A malicious version was published with a stolen npm personal access token. It did not go through
the GitHub Actions OIDC flow that every legitimate release from 1.3.0 onward used. Nothing about
the publish was unauthorised. What was wrong was the structure of the run: a publish effect with no
producing CI transition behind it.

Bundle: `fixtures/raw/capjs.json`, normalized to `fixtures/attack-capjs.json`.

MaskedRunner emits `registry_write npm-77120.0 has no producing transition`, and the rejection is
robust at maximum slack.

The control run is `fixtures/raw/capjs-provenance.json`: the same run, with genuine provenance for
the build that actually happened. It rejects at `slack=0` as explainable by unobserved steps, and
accepts at `--slack 1`. That control is what shows the detection is not simply "no publish job in
the log".

### keyv and family, 4 August 2026, and @7nohe/openapi-react-query-codegen, 28 August 2026

Poisoned releases published to npm with valid provenance signed by GitHub Actions. The flagship
package alone had 127M weekly downloads.

These are the argument for the project rather than a detection claim. Signed provenance answered
"who built it" correctly and still let the attack through, because provenance attests to the
identity of the builder, not to the legitimacy of the workflow that invoked it.

MaskedRunner adds the layer above: the publish has to be reachable in the declared workflow, from
an artifact that a preceding build in that workflow minted, fired by a principal the transition
admits. Whether it catches a specific provenance-signed compromise depends on whether the declared
spec forbids the path the attacker used. See the silence section below.

The forged-provenance held-out attack (`fixtures/attack-forged-provenance.json`) covers the
adjacent case, where the attacker fabricates the causal link itself. The relation constraint
`from.digest == to.digest` fails before the search even starts.

## Detectable in principle, not replayed here

### TeamPCP: Trivy, Checkmarx and others, 19 to 24 March 2026

A residual, incompletely rotated service account token from a February disclosure was used to
force-push across 110+ version tags in `trivy-action`, `setup-trivy`, `kics-github-action` and
`ast-github-action`, plus OpenVSX extensions and 66+ npm packages. Every git operation was
performed by an authorised identity.

The shape MaskedRunner reasons about here is a `vcs_write` effect against a release tag with no
producing release transition, repeated at a rate no single accepting path can account for.
Detecting it needs a spec covering the tagging workflow, which this repository does not ship.

### TanStack, 11 May 2026

A `pull_request_target` fork PR chained with GitHub Actions cache poisoning, then OIDC tokens
extracted from runner process memory. The build ran normally. The inputs did not.

This is a guard problem rather than a reachability problem. The transition fired legitimately, but
with an input the spec should have constrained. It is expressible as a guard on the checkout
transition binding the trigger event and the ref. Not shipped.

### The structural argument

Machine identities outnumber human accounts by a wide margin, reported between 45:1 and 144:1
depending on the source and the environment, and around two thirds of 2026 security incidents
involve them. Two properties make them resistant to the existing toolchain.

They bypass MFA by design, because there is no human to challenge. Their behavioural baseline also
carries almost no signal: they run 24/7, deterministically, and their whole purpose is repetitive
automated action, so anomaly detection has little to work with.

Detection has improved and revocation has not. Leaked credentials have been observed staying valid
for months, which is the window in which an attacker operates with a legitimate identity while
every individual step looks ordinary.

## Where it stays silent

Stated plainly, because a detector that claims to catch everything is not credible.

Attacks inside a permitted transition's declared blast radius pass. If the spec lets `deploy` write
anywhere, a write anywhere is accepted. The permissiveness meter reports the size of that blast
radius as a number instead of leaving it implicit.

A compromised spec signing key defeats the whole scheme, because nothing below the root of trust
helps.

Simultaneous suppression of every observation plane also defeats it. The trust assumption is that
at least one plane is honest. Which planes are assumed complete is declared per observation, and
any rejection that depends on that assumption is flagged in the certificate instead of being
presented as unconditional.

Malicious code inside a legitimately produced artifact passes. MaskedRunner verifies that the
workflow could have produced the artifact, not that its contents are benign. That is a scanner's
job.

## Sources

- Upwind, npm/PyPI supply chain campaign analysis (19 May 2026), on @cap-js/cds-mtxs PAT vs OIDC
- CSA Research Note, *TeamPCP CI/CD Supply Chain Compromise* (March 2026)
- Rescana, Snyk and Orca, TanStack GitHub Actions breach analysis (May 2026)
- Aikido, *keyv and friends compromised* (August 2026)
- Socket, `@7nohe/openapi-react-query-codegen` (August 2026)
- Cloud Security Alliance Lab Space, *The Non-Human Identity Governance Vacuum* (May 2026)
- GitGuardian, *State of Secrets Sprawl 2026*, and Palo Alto Networks, *2026 Identity Security Landscape*
- Cyber Strategy Institute, *2026 NHI Reality Report*, on credential validity persistence

The incident details above come from the analysis document this project was built from. The figures
are reproduced as reported there and have not been independently re-verified against the primary
sources.
