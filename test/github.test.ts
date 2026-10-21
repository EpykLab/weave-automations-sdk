import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import test from "node:test"
import { branchProtection, dependabot } from "../src/github.ts"
import { memoryStore } from "../src/store.ts"
import { CheckError, type CheckContext, type GitHubClient } from "../src/types.ts"

const scope = {
  organization: "EpykLab",
  reviewed_at: "2026-07-28",
  repositories: [
    { repository: "EpykLab/stllr", status: "in_scope" as const, control_families: ["branch_protection", "dependabot"] },
  ],
}

function ctx(client: GitHubClient, extra: Record<string, unknown> = {}): CheckContext {
  return {
    recipeId: "github-branch-protection",
    binding: { scope: "evidence/scope/github-repositories.json" },
    now: new Date("2026-10-21T00:00:00Z"),
    secret: () => "token",
    store: memoryStore(new Date("2026-10-21T00:00:00Z")),
    http: { async get() { throw new Error("unused") } },
    clients: { github: () => client },
    async scope() {
      return { document: { ...scope, ...extra } as never, digest: "digest" }
    },
    blocked: (message, detail) => new CheckError(message, "blocked", detail),
    failed: (message, detail) => new CheckError(message, "failed", detail),
    pending: (windowId) => new CheckError("pending", "pending", windowId),
  }
}

const compliantClassic = {
  required_status_checks: { contexts: ["ci"] },
  required_pull_request_reviews: { required_approving_review_count: 1 },
  enforce_admins: { enabled: true },
  allow_force_pushes: { enabled: false },
  allow_deletions: { enabled: false },
}

test("branch protection returns minimized fields for a compliant repository", async () => {
  const client: GitHubClient = {
    async paginate() {
      return [{ full_name: "EpykLab/stllr", created_at: "2026-01-01T00:00:00Z", default_branch: "master" }]
    },
    async get(path) {
      if (path === "/repos/EpykLab/stllr") return { full_name: "EpykLab/stllr", created_at: "2026-01-01T00:00:00Z", default_branch: "master" }
      return compliantClassic
    },
  }
  const result = await branchProtection.run(ctx(client)) as { compliant: boolean; repositories: Array<{ model: string; required_status_checks: string[] }> }
  assert.equal(result.compliant, true)
  assert.equal(result.repositories[0].model, "classic")
  assert.deepEqual(result.repositories[0].required_status_checks, ["ci"])
})

test("an existing unlisted repository stays out of scope", async () => {
  const client: GitHubClient = {
    async paginate() {
      return [
        { full_name: "EpykLab/stllr", created_at: "2026-01-01T00:00:00Z", default_branch: "master" },
        { full_name: "EpykLab/old-marketing", created_at: "2024-01-01T00:00:00Z", default_branch: "master" },
      ]
    },
    async get(path) {
      if (path === "/repos/EpykLab/stllr") return { full_name: "EpykLab/stllr", created_at: "2026-01-01T00:00:00Z", default_branch: "master" }
      return compliantClassic
    },
  }
  const result = await branchProtection.run(ctx(client, { existing_unlisted_status: "excluded" })) as { target_count: number }
  assert.equal(result.target_count, 1)
})

test("an existing unlisted repository blocks when the scope says unclassified", async () => {
  const client: GitHubClient = {
    async paginate() {
      return [
        { full_name: "EpykLab/stllr", created_at: "2026-01-01T00:00:00Z", default_branch: "master" },
        { full_name: "EpykLab/old-marketing", created_at: "2024-01-01T00:00:00Z", default_branch: "master" },
      ]
    },
    async get() { return null },
  }
  await assert.rejects(
    () => branchProtection.run(ctx(client, { existing_unlisted_status: "unclassified" })),
    (error: unknown) => error instanceof CheckError && error.kind === "blocked",
  )
})

test("a ruleset with no required status checks passes when that is the approved state", async () => {
  const client: GitHubClient = {
    async paginate(path) {
      if (String(path).includes("/rulesets")) return [{ id: 7 }]
      return [{ full_name: "EpykLab/stllr", created_at: "2026-01-01T00:00:00Z", default_branch: "master" }]
    },
    async get(path) {
      if (path === "/repos/EpykLab/stllr") return { full_name: "EpykLab/stllr", created_at: "2026-01-01T00:00:00Z", default_branch: "master" }
      if (path.endsWith("/protection")) return null
      return {
        enforcement: "active",
        target: "branch",
        bypass_actors: [],
        conditions: { ref_name: { include: ["~DEFAULT_BRANCH"] } },
        rules: [
          { type: "deletion" },
          { type: "non_fast_forward" },
          { type: "pull_request", parameters: { required_approving_review_count: 1 } },
        ],
      }
    },
  }
  const result = await branchProtection.run(ctx(client, {
    repositories: [{
      repository: "EpykLab/stllr",
      status: "in_scope",
      control_families: ["branch_protection"],
      expected: { required_status_checks: 0 },
    }],
  })) as { repositories: Array<{ required_status_checks: number }> }
  assert.equal(result.repositories[0].required_status_checks, 0)
})

test("an unclassified repository blocks branch protection", async () => {
  const client: GitHubClient = {
    async paginate() {
      return [
        { full_name: "EpykLab/stllr", created_at: "2026-01-01T00:00:00Z", default_branch: "master" },
        { full_name: "EpykLab/new", created_at: "2026-08-01T00:00:00Z", default_branch: "master" },
      ]
    },
    async get() { return null },
  }
  await assert.rejects(() => branchProtection.run(ctx(client)), (error: unknown) => error instanceof CheckError && error.kind === "blocked")
})

test("a ruleset fixture matches the collector's minimized fields", async () => {
  const protection = JSON.parse(await readFile(new URL("./fixtures/github-ruleset-protection-enabled.json", import.meta.url), "utf8"))
  const client: GitHubClient = {
    async paginate(path) {
      if (String(path).includes("/rulesets")) return [{ id: 7 }]
      return [{ full_name: "EpykLab/stllr", created_at: "2026-01-01T00:00:00Z", default_branch: "master" }]
    },
    async get(path) {
      if (path === "/repos/EpykLab/stllr") return { full_name: "EpykLab/stllr", created_at: "2026-01-01T00:00:00Z", default_branch: "master" }
      if (path.endsWith("/protection")) return null
      return protection
    },
  }
  const result = await branchProtection.run(ctx(client)) as { repositories: Array<Record<string, unknown>> }
  assert.deepEqual(result.repositories[0], {
    repository: "EpykLab/stllr",
    model: "ruleset",
    compliant: true,
    required_status_checks: 2,
    required_approving_review_count: 1,
    prevent_deletion: true,
    prevent_non_fast_forward: true,
  })
})

test("missing deletion protection fails the branch protection check", async () => {
  const client: GitHubClient = {
    async paginate() {
      return [{ full_name: "EpykLab/stllr", created_at: "2026-01-01T00:00:00Z", default_branch: "master" }]
    },
    async get(path) {
      if (path === "/repos/EpykLab/stllr") return { full_name: "EpykLab/stllr", created_at: "2026-01-01T00:00:00Z", default_branch: "master" }
      return { ...compliantClassic, allow_deletions: { enabled: true } }
    },
  }
  await assert.rejects(() => branchProtection.run(ctx(client)), (error: unknown) => error instanceof CheckError && error.kind === "failed")
})

test("an overdue high dependabot alert fails without an approved exception", async () => {
  const client: GitHubClient = {
    async paginate() {
      return [{ state: "open", number: 4, created_at: "2026-09-01T00:00:00Z", security_advisory: { severity: "high" } }]
    },
    async get() { return null },
  }
  await assert.rejects(() => dependabot.run(ctx(client)), (error: unknown) => error instanceof CheckError && error.kind === "failed")
})

test("an approved dependabot exception keeps the observation compliant", async () => {
  const client: GitHubClient = {
    async paginate() {
      return [{ state: "open", number: 4, created_at: "2026-09-01T00:00:00Z", security_advisory: { severity: "high" } }]
    },
    async get() { return null },
  }
  const result = await dependabot.run(ctx(client, {
    exceptions: [{ repository: "EpykLab/stllr", alert_number: 4, status: "approved", expires_at: "2026-12-01T00:00:00Z" }],
  })) as { compliant: boolean; repositories: Array<{ excepted_overdue: number; overdue_unexcepted: number }> }
  assert.equal(result.compliant, true)
  assert.equal(result.repositories[0].excepted_overdue, 1)
  assert.equal(result.repositories[0].overdue_unexcepted, 0)
})
