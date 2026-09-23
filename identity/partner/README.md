# Partner proposal

`sales-agent-harness.patch` is generated from the local proposal branch against
upstream commit `51efcee7d7680f8e3fe8444a4dbed029129caf94`.
The original repository is MIT-licensed by Shopware AG; these changes keep that
license. No upstream fork, push or PR has been published.

To prepare a disposable integration checkout without changing an existing clone:

```sh
bun run prepare:harness
bun run typecheck:integration
bun run test:integration
bun run demo
```

The preparation script clones the public repository, checks out the pinned base,
validates and applies this patch, then installs its locked dependencies without
lifecycle scripts. To reuse a local Git object source, pass its absolute path:
`bun run prepare:harness /path/to/sales-agent-harness-aithos`.
It refuses to reset or replace a different existing fixture.

The proposed API remains provider-neutral (`CallerAccess`, `RequestAdmission`).
See the included `docs/caller-admission-pilot.md` for the partner's wiring and
migration responsibilities. The Aithos service, credentials, runtime configuration
and partner policy are **not** hardcoded into the partner repository.
