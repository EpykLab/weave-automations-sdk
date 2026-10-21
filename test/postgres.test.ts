import assert from "node:assert/strict"
import { execFile } from "node:child_process"
import test from "node:test"
import { promisify } from "node:util"
import { connectPostgres, migrate, postgresStore } from "../src/postgres.ts"
import { posture } from "../src/kubernetes.ts"
import { context, readJSON } from "./helpers.ts"

const exec = promisify(execFile)
const container = "weave-actions-test"

test("postgres store shares one table and a read-only check writes nothing", async (t) => {
  await exec("docker", ["rm", "-f", container]).catch(() => undefined)
  await exec("docker", ["run", "-d", "--name", container, "-e", "POSTGRES_HOST_AUTH_METHOD=trust", "-e", "POSTGRES_DB=weave", "-p", "127.0.0.1:54329:5432", "postgres:16-alpine"])
  t.after(async () => {
    await exec("docker", ["rm", "-f", container]).catch(() => undefined)
  })
  const deadline = Date.now() + 30_000
  let ready = false
  while (Date.now() < deadline) {
    const result = await exec("docker", ["exec", container, "pg_isready", "-U", "postgres", "-d", "weave"]).then(() => true, () => false)
    if (result) {
      ready = true
      break
    }
    await new Promise((resolve) => setTimeout(resolve, 200))
  }
  if (!ready) throw new Error("postgres did not become ready")
  let db = connectPostgres("postgres://postgres@127.0.0.1:54329/weave")
  t.after(async () => {
    await db.end()
  })
  let migrated = false
  let last: unknown
  for (let attempt = 0; attempt < 30 && !migrated; attempt++) {
    try {
      await migrate(db)
      migrated = true
    } catch (error) {
      last = error
      await db.end().catch(() => undefined)
      await new Promise((resolve) => setTimeout(resolve, 300))
      db = connectPostgres("postgres://postgres@127.0.0.1:54329/weave")
    }
  }
  if (!migrated) throw last
  const store = postgresStore(db, new Date("2026-10-21T18:30:00Z"))
  const windowId = store.window("github-branch-protection", "send", 7 * 24 * 60 * 60 * 1000)
  await store.put({ recipeId: "github-branch-protection", action: "send", windowId, status: "accepted", deadline: "2026-10-22T00:00:00Z" })
  await store.put({ recipeId: "neon-backup-posture", action: "send", windowId, status: "accepted", deadline: "2026-10-22T00:00:00Z" })
  await store.put({ recipeId: "github-branch-protection", action: "send", windowId, status: "accepted", deadline: "2026-10-22T00:00:00Z" })
  const tables = await db.query("select table_name from information_schema.tables where table_schema = 'public' and table_name like 'weave%'")
  assert.deepEqual(tables.rows.map((row) => row.table_name), ["weave_actions"])
  const current = await store.current("github-branch-protection", "send")
  assert.equal(current?.windowId, "2026-10-15T00:00:00Z")
  const passing = {
    workloads: await readJSON("k8s-posture/workloads.json"),
    namespaces: await readJSON("k8s-posture/namespaces.json"),
    policies: await readJSON("k8s-posture/network-policies.json"),
    services: await readJSON("k8s-posture/services.json"),
  }
  await posture.run(context({ scope: {}, payload: passing }))
  const rows = await db.query("select count(*)::int as count from weave_actions where recipe_id = 'kubernetes-security-posture'")
  assert.equal(rows.rows[0].count, 0)
})
