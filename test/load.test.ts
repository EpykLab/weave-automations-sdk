import assert from "node:assert/strict"
import test from "node:test"
import { loadCheck } from "../src/load.ts"
import { memoryStore } from "../src/store.ts"
import { CheckError, type CheckContext } from "../src/types.ts"

const href = new URL("./fixtures/widget-check.ts", import.meta.url).href

test("a custom module loads by probe id", async () => {
  const check = await loadCheck(href, "acme.widget-health")
  const ctx: CheckContext = {
    recipeId: "widget",
    binding: { scope: "scope.json" },
    now: new Date(),
    secret: () => "",
    store: memoryStore(new Date()),
    http: { async get() { throw new Error("unused") } },
    clients: { github: () => { throw new Error("unused") } },
    async scope() { return { document: { ok: true } as never, digest: "abc" } },
    blocked: (message) => new CheckError(message, "blocked"),
    failed: (message) => new CheckError(message, "failed"),
    pending: (windowId) => new CheckError("pending", "pending", windowId),
  }
  const observation = await check.run(ctx) as { widget: string; scope_digest: string }
  assert.equal(observation.widget, "WIDGET_BODY")
  assert.equal(observation.scope_digest, "abc")
})

test("a custom module is rejected when the exported id does not match", async () => {
  await assert.rejects(() => loadCheck(href, "acme.other"), /acme.other/)
})
