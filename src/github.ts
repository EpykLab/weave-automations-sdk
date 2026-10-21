import { defineCheck } from "./define.ts"
import { CheckError, type Check, type CheckContext, type GitHubClient } from "./types.ts"

type ProtectionExpectation = {
  required_approving_review_count?: number
  required_status_checks?: number
  prevent_deletion?: boolean
  prevent_non_fast_forward?: boolean
  enforce_admins?: boolean
  allow_force_pushes?: boolean
  allow_deletions?: boolean
}

type ScopeRepo = {
  repository: string
  status: "in_scope" | "excluded" | "unclassified"
  control_families: string[]
  expected?: ProtectionExpectation
}

type GithubScope = {
  organization: string
  reviewed_at: string
  existing_unlisted_status?: "excluded" | "unclassified"
  newly_discovered_status?: "excluded" | "unclassified"
  repositories: ScopeRepo[]
}

type Repo = { full_name: string; created_at: string; default_branch: string }

type Protection = {
  required_status_checks?: { contexts?: string[] }
  required_pull_request_reviews?: { required_approving_review_count?: number }
  enforce_admins?: { enabled?: boolean }
  allow_force_pushes?: { enabled?: boolean }
  allow_deletions?: { enabled?: boolean }
  enforcement?: string
  target?: string
  bypass_actors?: unknown[]
  conditions?: { ref_name?: { include?: string[] } }
  rules?: Array<{
    type: string
    parameters?: { required_status_checks?: unknown[]; required_approving_review_count?: number }
  }>
}

export const branchProtection: Check = defineCheck({
  id: "github.branch-protection",
  secrets: ["GITHUB_TOKEN"],
  scopeKind: "github_repository_scope",
  async run(ctx) {
    const scope = await ctx.scope<GithubScope>(ctx.binding.scope)
    const gh = ctx.clients.github(ctx.secret("GITHUB_TOKEN"))
    const unclassified = await unclassifiedRepositories(gh, scope.document)
    if (unclassified.length > 0) throw ctx.blocked("unclassified repository found", { repositories: unclassified })
    const targets = scope.document.repositories.filter(
      (repo) => repo.status === "in_scope" && repo.control_families.includes("branch_protection"),
    )
    const failures: Array<{ repository: string; message: string; kind: "blocked" | "failed"; detail?: unknown }> = []
    const repositories = []
    await mapLimit(targets, 8, async (target) => {
      try {
        const repo = await gh.get<Repo>(`/repos/${target.repository}`)
        if (!repo) throw ctx.blocked("repository unavailable", { repository: target.repository })
        const protection = await loadProtection(ctx, gh, target.repository, repo.default_branch)
        const normalized = normalize(protection)
        if (!accepted(protection, normalized, target.expected)) throw ctx.failed("branch protection control failed", { repository: target.repository, protection: normalized })
        repositories.push({ repository: target.repository, ...normalized })
      } catch (error) {
        if (error instanceof CheckError && error.kind !== "pending") {
          failures.push({
            repository: target.repository,
            message: error.message,
            kind: error.kind === "failed" ? "failed" : "blocked",
            detail: error.detail,
          })
          return
        }
        throw error
      }
    })
    if (failures.length > 0) {
      const blocked = failures.some((failure) => failure.kind === "blocked")
      const message = (failures.find((failure) => failure.kind === (blocked ? "blocked" : "failed")) ?? failures[0]).message
      throw blocked ? ctx.blocked(message, { repositories: failures }) : ctx.failed(message, { repositories: failures })
    }
    return { compliant: true, scope_digest: scope.digest, target_count: repositories.length, repositories }
  },
})

async function unclassifiedRepositories(gh: GitHubClient, scope: GithubScope) {
  const discovered = await gh.paginate<Repo>(`/orgs/${scope.organization}/repos?type=all&per_page=100`)
  const classified = new Set(scope.repositories.map((repo) => repo.repository))
  const cutoff = `${scope.reviewed_at}T23:59:59Z`
  const existing = scope.existing_unlisted_status ?? "excluded"
  const discoveredStatus = scope.newly_discovered_status ?? "unclassified"
  return discovered.filter((repo) => {
    if (!repo.full_name || classified.has(repo.full_name)) return false
    const status = repo.created_at > cutoff ? discoveredStatus : existing
    return status === "unclassified"
  }).map((repo) => repo.full_name)
}

function accepted(protection: Protection, normalized: ReturnType<typeof normalize>, expected?: ProtectionExpectation) {
  if (!expected) return normalized.compliant
  if (protection.target === "branch" && (protection.bypass_actors ?? []).length > 0) return false
  const reviews = normalized.required_approving_review_count
  const checks = Array.isArray(normalized.required_status_checks) ? normalized.required_status_checks.length : normalized.required_status_checks
  const reviewsOk = expected.required_approving_review_count === undefined ? reviews >= 1 : reviews === expected.required_approving_review_count
  const checksOk = expected.required_status_checks === undefined ? checks > 0 : checks === expected.required_status_checks
  if (normalized.model === "ruleset") {
    return reviewsOk && checksOk && normalized.prevent_deletion === (expected.prevent_deletion ?? true) && normalized.prevent_non_fast_forward === (expected.prevent_non_fast_forward ?? true)
  }
  return reviewsOk && checksOk && normalized.enforce_admins === (expected.enforce_admins ?? true) && normalized.allow_force_pushes === (expected.allow_force_pushes ?? false) && normalized.allow_deletions === (expected.allow_deletions ?? false)
}

async function loadProtection(ctx: CheckContext, gh: GitHubClient, repository: string, branch: string): Promise<Protection> {
  const classic = await gh.get<Protection>(`/repos/${repository}/branches/${branch}/protection`, { allowMissing: true })
  if (classic) return classic
  const rulesets = await gh.paginate<{ id: number }>(`/repos/${repository}/rulesets`)
  const full = await Promise.all(rulesets.map((ruleset) => gh.get<Protection>(`/repos/${repository}/rulesets/${ruleset.id}`)))
  const match = full.find(
    (ruleset) =>
      ruleset?.enforcement === "active" &&
      ruleset.target === "branch" &&
      ruleset.conditions?.ref_name?.include?.includes("~DEFAULT_BRANCH"),
  )
  if (!match) throw ctx.blocked("no active default-branch ruleset", { repository })
  return match
}

function normalize(protection: Protection) {
  if (protection.target === "branch" && Array.isArray(protection.rules)) {
    const rules = protection.rules
    const reviews = rules.find((rule) => rule.type === "pull_request")
    const checks = rules.filter((rule) => rule.type === "required_status_checks")
    const compliant =
      protection.enforcement === "active" &&
      (protection.conditions?.ref_name?.include ?? []).includes("~DEFAULT_BRANCH") &&
      (protection.bypass_actors ?? []).length === 0 &&
      rules.some((rule) => rule.type === "deletion") &&
      rules.some((rule) => rule.type === "non_fast_forward") &&
      checks.some((rule) => (rule.parameters?.required_status_checks ?? []).length > 0) &&
      (reviews?.parameters?.required_approving_review_count ?? 0) >= 1
    return {
      model: "ruleset" as const,
      compliant,
      required_status_checks: checks.flatMap((rule) => rule.parameters?.required_status_checks ?? []).length,
      required_approving_review_count: reviews?.parameters?.required_approving_review_count ?? 0,
      prevent_deletion: rules.some((rule) => rule.type === "deletion"),
      prevent_non_fast_forward: rules.some((rule) => rule.type === "non_fast_forward"),
    }
  }
  const contexts = [...(protection.required_status_checks?.contexts ?? [])].sort()
  const compliant =
    contexts.length > 0 &&
    (protection.required_pull_request_reviews?.required_approving_review_count ?? 0) >= 1 &&
    protection.enforce_admins?.enabled === true &&
    protection.allow_force_pushes?.enabled === false &&
    protection.allow_deletions?.enabled === false
  return {
    model: "classic" as const,
    compliant,
    required_status_checks: contexts,
    required_approving_review_count: protection.required_pull_request_reviews?.required_approving_review_count ?? 0,
    enforce_admins: protection.enforce_admins?.enabled === true,
    allow_force_pushes: protection.allow_force_pushes?.enabled === true,
    allow_deletions: protection.allow_deletions?.enabled === true,
  }
}

type Alert = { state?: string; number?: number; created_at?: string; security_advisory?: { severity?: string } }
type Exception = { repository: string; alert_number: number; status: string; expires_at: string }

export const dependabot: Check = defineCheck({
  id: "github.dependabot",
  secrets: ["GITHUB_TOKEN"],
  scopeKind: "github_repository_scope",
  async run(ctx) {
    const scope = await ctx.scope<GithubScope & { exceptions?: Exception[] }>(ctx.binding.scope)
    const gh = ctx.clients.github(ctx.secret("GITHUB_TOKEN"))
    const unclassified = await unclassifiedRepositories(gh, scope.document)
    if (unclassified.length > 0) throw ctx.blocked("unclassified repository found", { repositories: unclassified })
    const asOf = ctx.now
    const targets = scope.document.repositories.filter(
      (repo) => repo.status === "in_scope" && repo.control_families.includes("dependabot"),
    )
    const failures: Array<{ repository: string; message: string }> = []
    const repositories = []
    await mapLimit(targets, 8, async (target) => {
      try {
        const alerts = await gh.paginate<Alert>(`/repos/${target.repository}/dependabot/alerts`)
        repositories.push(summarize(target.repository, alerts, scope.document.exceptions ?? [], asOf))
      } catch (error) {
        if (error instanceof CheckError) {
          failures.push({ repository: target.repository, message: error.message })
          return
        }
        throw error
      }
    })
    if (failures.length > 0) throw ctx.blocked("dependabot alerts are not assessable", { repositories: failures })
    const compliant = repositories.every((repo) => repo.overdue_unexcepted === 0 && repo.unassessable === 0)
    if (!compliant) throw ctx.failed("dependabot alerts exceed remediation SLA")
    return { compliant, scope_digest: scope.digest, evaluated_at: asOf.toISOString(), target_count: repositories.length, repositories }
  },
})

async function mapLimit<T, R>(items: T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length)
  let next = 0
  const workers = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next
      next += 1
      results[index] = await fn(items[index])
    }
  })
  await Promise.all(workers)
  return results
}

function summarize(repository: string, alerts: Alert[], exceptions: Exception[], asOf: Date) {
  const open = alerts.filter((alert) => alert.state === "open").map((alert) => {
    const severity = alert.security_advisory?.severity ?? "unknown"
    const sla = severity === "critical" ? 15 * 86400 : severity === "high" ? 20 * 86400 : null
    const created = alert.created_at ? Date.parse(alert.created_at) : Number.NaN
    const overdue = sla !== null && (Number.isNaN(created) || asOf.getTime() - created > sla * 1000)
    const excepted = overdue && exceptions.some(
      (item) => item.repository === repository && item.alert_number === alert.number && item.status === "approved" && item.expires_at >= asOf.toISOString(),
    )
    return { severity, overdue, excepted, unassessable: sla !== null && Number.isNaN(created) }
  })
  const count = (severity: string, pred?: (item: (typeof open)[number]) => boolean) =>
    open.filter((item) => item.severity === severity && (pred ? pred(item) : true)).length
  return {
    repository,
    open: { total: open.length, critical: count("critical"), high: count("high"), medium: count("medium"), low: count("low") },
    within_sla: { critical: count("critical", (item) => !item.overdue), high: count("high", (item) => !item.overdue) },
    excepted_overdue: open.filter((item) => item.overdue && item.excepted).length,
    overdue_unexcepted: open.filter((item) => item.overdue && !item.excepted).length,
    unassessable: open.filter((item) => item.unassessable).length,
  }
}
