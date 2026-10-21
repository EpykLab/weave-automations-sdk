import assert from "node:assert/strict"
import test from "node:test"
import { accessCaller } from "../src/auth.ts"
import { defineCheck } from "../src/define.ts"
import { memoryStore } from "../src/store.ts"
import { serve } from "../src/router.ts"

const subjects = [
  {
    name: "daily",
    issuer: "https://token.actions.githubusercontent.com",
    repository: "EpykLab/stllr-weave",
    workflow: "evidence-daily.yml",
    allow: ["recipe:*:run"],
  },
  {
    name: "operators",
    issuer: "weave",
    allow: ["recipe:*:run", "recipe:fedramp-security-inbox:act"],
  },
]

test("a matching workflow can run and cannot send", () => {
  const caller = accessCaller(subjects, {
    issuer: "https://token.actions.githubusercontent.com",
    subject: "daily",
    repository: "EpykLab/stllr-weave",
    workflow: "evidence-daily.yml",
  })
  assert.equal(caller?.allows("neon-backup-posture", "run"), true)
  assert.equal(caller?.allows("fedramp-security-inbox", "act"), false)
})

test("a workflow that does not match the subject is rejected", () => {
  const caller = accessCaller(subjects, {
    issuer: "https://token.actions.githubusercontent.com",
    subject: "daily",
    repository: "EpykLab/stllr-weave",
    workflow: "other.yml",
  })
  assert.equal(caller, undefined)
})

test("an operator token cannot read provider secrets", async () => {
  let read = false
  const handle = serve({
    recipes: [{
      id: "github-branch-protection",
      check: defineCheck({
        id: "example",
        secrets: ["GITHUB_TOKEN"],
        scopeKind: "example",
        async run(ctx) {
          ctx.secret("GITHUB_TOKEN")
          read = true
          return {}
        },
      }),
      scope: "scope.json",
      schedule: "weekly",
    }],
    authenticate: () => accessCaller(subjects, { issuer: "weave", subject: "operators" }),
    store: memoryStore(new Date()),
    now: () => new Date(),
    readScope: async () => ({}),
    secret(name) {
      read = true
      return name
    },
    clients: { github: () => { throw new Error("unused") } },
  })
  const response = await handle({ method: "POST", path: "/recipes/github-branch-protection/runs", token: "operator" })
  assert.equal(response.status, 422)
  assert.equal(read, false)
})
