import assert from "node:assert/strict"
import test from "node:test"
import { memoryStore } from "../src/store.ts"

const week = 7 * 24 * 60 * 60 * 1000

test("a weekly window is stable and a repeated put keeps one row", async () => {
  const store = memoryStore(new Date("2026-10-21T18:30:00Z"))
  const windowId = store.window("fedramp-security-inbox", "send", week)
  assert.equal(windowId, "2026-10-15T00:00:00Z")
  const row = { recipeId: "fedramp-security-inbox", action: "send", windowId, status: "accepted" as const, deadline: "2026-10-21T18:35:00Z" }
  await store.put(row)
  await store.put(row)
  assert.deepEqual(await store.current("fedramp-security-inbox", "send"), row)
})

test("a read-only recipe does not need a coordination row", async () => {
  const store = memoryStore(new Date("2026-10-21T18:30:00Z"))
  assert.equal(await store.current("kubernetes-security-posture", "send"), null)
})
