import assert from "node:assert/strict"
import { createSign, generateKeyPairSync, type JsonWebKey } from "node:crypto"
import { mkdir, mkdtemp, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import test from "node:test"
import { serve } from "../src/digitalocean.ts"
import { defineCheck } from "../src/define.ts"
import { branchProtection } from "../src/github.ts"
import { actionsAudience, actionsIssuer } from "../src/oidc.ts"
import { memoryStore } from "../src/store.ts"
import { CheckError } from "../src/types.ts"

const check = defineCheck({
  id: "example.check",
  secrets: [],
  scopeKind: "example",
  async run(ctx) {
    const scope = await ctx.scope<{ value: string }>(ctx.binding.scope)
    if (scope.document.value === "wait") throw ctx.pending("2026-10-15T00:00:00Z")
    return { compliant: true, value: scope.document.value }
  },
})

function main(value: string) {
  return serve({
    group: "inventory",
    recipes: [{ id: "github-branch-protection", check, scope: "scope.json", schedule: "weekly" }],
    authenticate: () => ({ subject: "daily", allows: () => true }),
    store: memoryStore(new Date("2026-10-21T18:30:00Z")),
    now: () => new Date("2026-10-21T18:30:00Z"),
    readScope: async () => ({ value }),
    secret: () => "",
    clients: { github: () => { throw new Error("unused") } },
  })
}

test("a DigitalOcean web action round-trips a successful run", async () => {
  const response = await main("ok")({
    __ow_method: "POST",
    __ow_path: "/recipes/github-branch-protection/runs",
    __ow_headers: { authorization: "Bearer daily" },
  })
  assert.equal(response.statusCode, 200)
  const body = response.body as { run: { status: string; artifacts: Array<{ body: { value: string } }> } }
  assert.equal(body.run.status, "complete")
  assert.equal(body.run.artifacts[0].body.value, "ok")
})

test("a DigitalOcean web action accepts the lowercase method OpenWhisk sends", async () => {
  const response = await main("ok")({
    __ow_method: "post",
    __ow_path: "/recipes/github-branch-protection/runs",
    __ow_headers: { authorization: "Bearer daily" },
  })
  assert.equal(response.statusCode, 200)
})

test("a GitHub Actions workflow token is accepted for its repository and workflow file", async () => {
  const { token, other, jwk } = signedWorkflows()
  const dir = await mkdtemp(path.join(tmpdir(), "weave-adapter-"))
  await writeFile(path.join(dir, "access.json"), JSON.stringify({
    subjects: [{
      name: "daily",
      issuer: actionsIssuer,
      repository: "EpykLab/stllr-weave",
      workflow: "evidence-daily.yml",
      allow: ["recipe:*:run"],
    }],
  }))
  const previous = process.cwd()
  const previousFetch = globalThis.fetch
  process.chdir(dir)
  globalThis.fetch = (async (url: string) => {
    assert.equal(url, `${actionsIssuer}/.well-known/jwks`)
    return { ok: true, async json() { return { keys: [jwk] } } }
  }) as typeof fetch
  try {
    const handler = serve({
      group: "inventory",
      recipes: [{ id: "neon-backup-posture", check, scope: "scope.json", schedule: "weekly" }],
    })
    const accepted = await handler({ __ow_method: "get", __ow_path: "/recipes", __ow_headers: { authorization: `Bearer ${token}` } })
    assert.equal(accepted.statusCode, 200)
    assert.deepEqual(accepted.body, { recipes: ["neon-backup-posture"] })
    const rejected = await handler({ __ow_method: "get", __ow_path: "/recipes", __ow_headers: { authorization: `Bearer ${other}` } })
    assert.equal(rejected.statusCode, 401)
  } finally {
    process.chdir(previous)
    globalThis.fetch = previousFetch
  }
})

test("the platform adapter blocks an operator token before it calls a provider", async () => {
  const dir = await mkdtemp(path.join(tmpdir(), "weave-adapter-"))
  await writeFile(path.join(dir, "access.json"), JSON.stringify({
    subjects: [{ name: "operators", issuer: "weave", allow: ["recipe:*:run"] }],
  }))
  await mkdir(path.join(dir, "scopes"))
  await writeFile(path.join(dir, "scopes", "github-repositories.json"), JSON.stringify({ organization: "EpykLab", reviewed_at: "2026-07-28", repositories: [] }))
  const previous = process.cwd()
  const previousToken = process.env.OPERATOR_TOKEN
  process.chdir(dir)
  process.env.OPERATOR_TOKEN = "operator-token"
  try {
    const response = await serve({
      group: "inventory",
      recipes: [{ id: "github-branch-protection", check: branchProtection, scope: "evidence/scope/github-repositories.json", schedule: "weekly" }],
    })({
      __ow_method: "post",
      __ow_path: "/recipes/github-branch-protection/runs",
      __ow_headers: { authorization: "Bearer operator-token" },
    })
    assert.equal(response.statusCode, 422)
    assert.equal((response.body as { message: string }).message, "operator token cannot read provider secrets")
  } finally {
    process.chdir(previous)
    if (previousToken === undefined) delete process.env.OPERATOR_TOKEN
    else process.env.OPERATOR_TOKEN = previousToken
  }
})

test("a DigitalOcean web action round-trips pending", async () => {
  const response = await main("wait")({
    __ow_method: "POST",
    __ow_path: "/recipes/github-branch-protection/runs",
    __ow_headers: { authorization: "Bearer daily" },
  })
  assert.equal(response.statusCode, 202)
  assert.deepEqual(response.body, { status: "pending", window_id: "2026-10-15T00:00:00Z" })
})

void CheckError

function signedWorkflows() {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
  const jwk = publicKey.export({ format: "jwk" }) as JsonWebKey
  jwk.kid = "test"
  const now = Math.floor(Date.now() / 1000)
  const sign = (workflow: string) => {
    const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "test" })).toString("base64url")
    const body = Buffer.from(JSON.stringify({
      iss: actionsIssuer,
      aud: actionsAudience,
      exp: now + 600,
      nbf: now - 10,
      repository: "EpykLab/stllr-weave",
      workflow_ref: `EpykLab/stllr-weave/.github/workflows/${workflow}@refs/heads/master`,
    })).toString("base64url")
    const signature = createSign("RSA-SHA256").update(`${header}.${body}`).sign(privateKey).toString("base64url")
    return `${header}.${body}.${signature}`
  }
  return { token: sign("evidence-daily.yml"), other: sign("other.yml"), jwk }
}
