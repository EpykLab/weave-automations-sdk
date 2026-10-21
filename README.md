# Weave Automations SDK

Checks, actions, and runtime adapters for Weave automation recipes.

## Install

```sh
npm install @epyklabdotcom/automations
```

Requires Node.js 22.18.0 or later. This package is ESM-only and includes TypeScript declarations.

## Define a check

```ts
import { defineCheck } from "@epyklabdotcom/automations"

export default defineCheck({
  id: "example.inventory",
  secrets: [],
  scopeKind: "example_scope",
  async run(ctx) {
    const scope = await ctx.scope<{ approved: boolean }>(ctx.binding.scope)
    if (!scope.document.approved) {
      throw ctx.failed("scope is not approved")
    }
    return { compliant: true, scope_digest: scope.digest }
  },
})
```

Checks run with a `CheckContext` supplied by the runtime. It provides scoped documents, provider clients, secret access, action coordination, and helpers for blocked, failed, and pending results.

## Entry points

| Import | Contents |
| --- | --- |
| `@epyklabdotcom/automations` | Check and action definitions, GitHub checks, scope digests, in-memory store, router, and shared types |
| `@epyklabdotcom/automations/digitalocean` | DigitalOcean web action adapter |
| `@epyklabdotcom/automations/github` | Branch protection and Dependabot checks |
| `@epyklabdotcom/automations/neon` | Backup posture check |
| `@epyklabdotcom/automations/azure` | Security inbox, offering inventory, and Key Vault audit checks |
| `@epyklabdotcom/automations/inventory` | Auth0, Cloudflare, DigitalOcean Valkey, Fly, Tigris, Elastic, and TLS checks |
| `@epyklabdotcom/automations/resend` | Account inventory check and delivery test action |
| `@epyklabdotcom/automations/kubernetes` | Workload, namespace, network isolation, and application configuration checks |

## Development

```sh
npm ci
npm test
npm run build
npm run test:package
```

`npm pack` builds JavaScript and declarations into `dist/`. The published package includes `dist/` and SQL migrations, but excludes source tests and fixtures.

## Publishing

CI tests Node.js 22.18.0 and 24 on pull requests and pushes to `master`. It runs the test suite, strict build, and an installed-tarball check of every public entry point and its TypeScript declarations. The tests require Docker for their temporary PostgreSQL container; GitHub-hosted Ubuntu runners provide it.

### One-time npm setup

The first version must be published by an npm account with access to the `epyklabdotcom` organization:

```sh
npm whoami
npm publish --dry-run
npm publish --access public
```

After the package exists, configure a GitHub Actions trusted publisher using npm 12.2.0 or later (requires account-level 2FA):

```sh
npm trust github @epyklabdotcom/automations \
  --repo EpykLab/weave-automations-sdk \
  --file publish.yml \
  --allow-publish \
  --yes
npm trust list @epyklabdotcom/automations
```

Alternatively, use the package's trusted publisher settings on npmjs.com: organization `EpykLab`, repository `weave-automations-sdk`, workflow filename `publish.yml`, no environment, and direct `npm publish` allowed.

No `NPM_TOKEN` GitHub secret is needed. Newly configured trusted publishers must complete their first successful publish within two days; otherwise recreate the configuration. After verifying a CI publish, npm recommends selecting "Require two-factor authentication and disallow tokens" in the package's publishing access settings.

This repository is private, so npm provenance attestations are unavailable. Trusted publishing still authenticates the workflow using OIDC. If the repository becomes public, npm can generate provenance automatically.

### Release a new version

1. Update the version and lockfile with `npm version patch` (or `minor`/`major`). This creates a commit and a `v`-prefixed tag; start from a clean checkout.
2. Push the version commit and its tag, for example `git push origin master && git push origin v0.1.1`.
3. Publish a GitHub Release for that tag. The tag must match `package.json`, for example `v0.1.1`.

Publishing a GitHub Release triggers `.github/workflows/publish.yml`, which verifies the version, runs tests, tests the installed tarball, and publishes to npm using OIDC. A version bump or tag push alone does not publish. GitHub prereleases must use a prerelease version such as `0.2.0-beta.1`; they publish under npm's `next` tag rather than `latest`.

Each npm version is immutable. If the first version was published manually, start automated releases with the next version rather than trying to republish it.

## License

Apache-2.0. See [LICENSE](LICENSE).
