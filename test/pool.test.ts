import assert from "node:assert/strict"
import test from "node:test"
import { readFile } from "node:fs/promises"
import { requirePooled } from "../src/pool.ts"

test("the function runtime rejects a direct Neon host", () => {
  assert.throws(
    () => requirePooled("postgresql://user:pw@ep-cool.us-west-2.aws.neon.tech/weave?sslmode=require"),
    /pooled/,
  )
  assert.equal(
    requirePooled("postgresql://user:pw@ep-cool-pooler.us-west-2.aws.neon.tech/weave?sslmode=require"),
    "postgresql://user:pw@ep-cool-pooler.us-west-2.aws.neon.tech/weave?sslmode=require",
  )
})

test("the coordination migration keys rows by recipe, action, and window", async () => {
  const sql = await readFile(new URL("../migrations/001_weave_actions.sql", import.meta.url), "utf8")
  assert.match(sql, /primary key \(recipe_id, action, window_id\)/)
  assert.match(sql, /create table if not exists weave_actions/)
})
