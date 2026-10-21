import assert from "node:assert/strict"
import test from "node:test"
import { defineAction, defineCheck } from "../src/define.ts"
import { memoryStore } from "../src/store.ts"
import { serve } from "../src/router.ts"
import type { Caller, CheckContext } from "../src/types.ts"

const check = defineCheck({
  id: "example.check",
  secrets: [],
  scopeKind: "example",
  async run(ctx) {
    const scope = await ctx.scope<{ value: string }>(ctx.binding.scope)
    if (scope.document.value === "fail") throw ctx.failed("control failed")
    if (scope.document.value === "wait") throw ctx.pending("2026-10-15T00:00:00Z")
    return { compliant: true, scope_digest: scope.digest, value: scope.document.value }
  },
})

let sends = 0
const action = defineAction({
  id: "example.send",
  secrets: [],
  scopeKind: "example",
  async run(ctx) {
    const windowId = ctx.store.window(ctx.recipeId, "send", 7 * 24 * 60 * 60 * 1000)
    const existing = await ctx.store.current(ctx.recipeId, "send")
    if (existing?.windowId === windowId) return { window_id: windowId }
    await ctx.store.put({
      recipeId: ctx.recipeId,
      action: "send",
      windowId,
      status: "accepted",
      deadline: "2026-10-21T18:35:00Z",
    })
    sends += 1
    return { window_id: windowId, retry: { budget_ms: 300_000 } }
  },
})

function app(allows: Caller["allows"]) {
  return serve({
    recipes: [
      {
        id: "github-branch-protection",
        check,
        scope: "evidence/scope/example.json",
        schedule: "weekly",
        action: { use: action, schedule: "weekly", retry: { budgetMs: 300_000 } },
      },
    ],
    authenticate(token) {
      if (token === "nope") return undefined
      return { subject: token, allows }
    },
    store: memoryStore(new Date("2026-10-21T18:30:00Z")),
    now: () => new Date("2026-10-21T18:30:00Z"),
    async readScope() {
      return { value: "ok" }
    },
    secret: () => "",
    clients: { github: () => { throw new Error("unused") } },
  })
}

const runOnly: Caller["allows"] = (_recipe, operation) => operation === "run"
const actOnly: Caller["allows"] = (recipe, operation) => recipe === "github-branch-protection" && operation === "act"

test("a request without a token does not run the check", async () => {
  let called = false
  const handle = serve({
    recipes: [{ id: "github-branch-protection", check: { ...check, run: async () => { called = true; return {} } }, scope: "s", schedule: "weekly" }],
    authenticate: () => undefined,
    store: memoryStore(new Date()),
    now: () => new Date(),
    readScope: async () => ({}),
    secret: () => "",
    clients: { github: () => { throw new Error("unused") } },
  })
  const response = await handle({ method: "POST", path: "/recipes/github-branch-protection/runs" })
  assert.equal(response.status, 401)
  assert.equal(called, false)
})

test("catalog lists only recipes the caller may run", async () => {
  const response = await app(runOnly)({ method: "GET", path: "/recipes", token: "daily" })
  assert.deepEqual(response.body, { recipes: ["github-branch-protection"] })
})

test("a run-only caller cannot send", async () => {
  const response = await app(runOnly)({ method: "POST", path: "/recipes/github-branch-protection/actions/example.send", token: "daily" })
  assert.equal(response.status, 403)
})

test("a successful check returns a completed run and not the provider secret", async () => {
  const response = await app(runOnly)({ method: "POST", path: "/recipes/github-branch-protection/runs", token: "daily" })
  assert.equal(response.status, 200)
  const body = response.body as { run: { status: string; artifacts: Array<{ body: { value: string } }> } }
  assert.equal(body.run.status, "complete")
  assert.equal(body.run.artifacts[0].body.value, "ok")
  assert.equal(JSON.stringify(body).includes("secret"), false)
})

test("a failed assertion is not a completed run", async () => {
  const handle = app(runOnly)
  const failing = serve({
    recipes: [{ id: "github-branch-protection", check, scope: "s", schedule: "weekly" }],
    authenticate: () => ({ subject: "daily", allows: runOnly }),
    store: memoryStore(new Date()),
    now: () => new Date(),
    readScope: async () => ({ value: "fail" }),
    secret: () => "",
    clients: { github: () => { throw new Error("unused") } },
  })
  const response = await failing({ method: "POST", path: "/recipes/github-branch-protection/runs", token: "daily" })
  assert.equal(response.status, 422)
  assert.equal(JSON.stringify(response.body).includes('"status":"complete"'), false)
  void handle
})

test("pending is not a completed run", async () => {
  const handle = serve({
    recipes: [{ id: "fedramp-security-inbox", check, scope: "s", schedule: "daily" }],
    authenticate: () => ({ subject: "daily", allows: () => true }),
    store: memoryStore(new Date()),
    now: () => new Date(),
    readScope: async () => ({ value: "wait" }),
    secret: () => "",
    clients: { github: () => { throw new Error("unused") } },
  })
  const response = await handle({ method: "POST", path: "/recipes/fedramp-security-inbox/runs", token: "daily" })
  assert.equal(response.status, 202)
  assert.deepEqual(response.body, { status: "pending", window_id: "2026-10-15T00:00:00Z" })
})

test("repeating an action in the same window does not send twice", async () => {
  sends = 0
  const handle = app(actOnly)
  const first = await handle({ method: "POST", path: "/recipes/github-branch-protection/actions/example.send", token: "inbox" })
  const second = await handle({ method: "POST", path: "/recipes/github-branch-protection/actions/example.send", token: "inbox" })
  assert.equal(first.status, 202)
  assert.equal((second.body as { window_id: string }).window_id, "2026-10-15T00:00:00Z")
  assert.equal(sends, 1)
})

void (null as unknown as CheckContext)
