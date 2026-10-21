import assert from "node:assert/strict"
import test from "node:test"
import { backupPosture } from "../src/neon.ts"
import { memoryStore } from "../src/store.ts"
import { CheckError, type CheckContext } from "../src/types.ts"

test("neon backup posture accepts a project whose approved retention is six hours", async () => {
  const result = await backupPosture.run(ctx([
      { id: "preview", name: "stllr-preview", history_retention_seconds: 21600, region_id: "aws-us-west-2" },
      { id: "app", name: "stllr-app", history_retention_seconds: 604800, region_id: "aws-us-west-2" },
    ], {
    projects: [
      { project_id: "preview", project_name: "stllr-preview", status: "in_scope", history_retention_seconds: 21600 },
      { project_id: "app", project_name: "stllr-app", status: "in_scope" },
    ],
  })) as { compliant: boolean; projects: Array<{ history_retention_seconds?: number }> }
  assert.equal(result.compliant, true)
  assert.deepEqual(result.projects.map((project) => project.history_retention_seconds), [21600, 604800])
})

test("neon backup posture fails when live retention differs from the approved state", async () => {
  await assert.rejects(
    () => backupPosture.run(ctx(
      [{ id: "preview", name: "stllr-preview", history_retention_seconds: 604800 }],
      { projects: [{ project_id: "preview", project_name: "stllr-preview", status: "in_scope", history_retention_seconds: 21600 }] },
    )),
    (error: unknown) => error instanceof CheckError && error.kind === "failed" && error.message.includes("approved state"),
  )
})

test("neon backup posture reads the live project list when no fixture payload is configured", async () => {
  const original = globalThis.fetch
  globalThis.fetch = (async () => new Response(JSON.stringify({
    projects: [
      { id: "proj-1", name: "stllr-app", history_retention_seconds: 604800, region_id: "aws-us-west-2" },
    ],
  }))) as typeof fetch
  try {
    const result = await backupPosture.run(ctx()) as { compliant: boolean; projects: Array<{ history_retention_seconds?: number }> }
    assert.equal(result.compliant, true)
    assert.equal(result.projects[0].history_retention_seconds, 604800)
  } finally {
    globalThis.fetch = original
  }
})

function ctx(payload?: unknown, scope?: Record<string, unknown>): CheckContext {
  return {
    recipeId: "neon-backup-posture",
    binding: { scope: "evidence/scope/neon-projects.json" },
    now: new Date("2026-10-21T00:00:00Z"),
    secret: () => "neon-token",
    store: memoryStore(new Date("2026-10-21T00:00:00Z")),
    http: { async get() { throw new Error("unused") } },
    clients: { github: () => { throw new Error("unused") }, payload: payload === undefined ? undefined : async () => payload },
    async scope() {
      return {
        document: {
          org_id: "org-1",
          projects: [{ project_id: "proj-1", project_name: "stllr-app", status: "in_scope" }],
          ...scope,
        } as never,
        digest: "digest",
      }
    },
    blocked: (message, detail) => new CheckError(message, "blocked", detail),
    failed: (message, detail) => new CheckError(message, "failed", detail),
    pending: (windowId) => new CheckError("pending", "pending", windowId),
  }
}
