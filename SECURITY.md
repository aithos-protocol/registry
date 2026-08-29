# Security

This registry's whole product is a security property: that an entry can only
be changed by a holder of its authorized keys. If you have found a way to
falsify that — or any way to make the registry serve something its register
does not say — we want to know quietly, before anyone else does.

## Reporting

Use GitHub's private vulnerability reporting on this repository:
**Security → Report a vulnerability**. That opens a private advisory thread
with the maintainer and nothing public.

Please do not open a public issue for anything you believe is exploitable, and
do not demonstrate a finding against entries you do not own —
`registry-dev.aithos.world` is a real, append-only register, and what is
published there cannot be unpublished.

## Scope

- the crates in this repository (`aithos-a2a-card`, `aithos-registry-core`,
  `registry-api`, `registry-lambda`, and the `aithos` CLI);
- the deployed registry service and its edge configuration;
- the release pipeline and its attestations.

Findings about A2A itself belong upstream with the
[A2A project](https://github.com/a2aproject/A2A). Findings about a card's
*content* — a dishonest `name`, an endpoint the key holder does not operate —
are not vulnerabilities: the specification is explicit that nobody checked
those claims (`SPEC.md` §10), and every interface this project ships says so
out loud.

## What to expect

An acknowledgement within a few days, an honest conversation about impact and
timing, and credit if you want it. There is no bounty programme.

Ten rounds of adversarial review, and every decision they produced, are public
in [`audits/`](audits/). Reading `audits/LEDGER.md` first may save you from
re-finding something already found — and shows the standard a finding is held
to here: a concrete failure scenario, confirmed by execution where possible.
