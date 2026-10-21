import { defineCheck } from "./define.ts"
import type { Check, CheckContext } from "./types.ts"

const sevenDays = 604800

type NeonProject = { id?: string; name?: string; region_id?: string; history_retention_seconds?: number; project?: { id?: string; region_id?: string; settings?: { history_retention_seconds?: number } }; connection_uri?: string }

export const backupPosture: Check = defineCheck({
  id: "neon.backup-posture",
  secrets: ["NEON_API_KEY"],
  scopeKind: "neon_project_scope",
  async run(ctx) {
    const scope = await ctx.scope<{ projects?: Array<{ project_id: string; project_name: string; status: string; history_retention_seconds?: number }> }>(ctx.binding.scope)
    const payload = await readPayload<NeonProject | NeonProject[]>(ctx)
    if (payload && !Array.isArray(payload) && payload.project) {
      const seconds = payload.project.settings?.history_retention_seconds ?? 0
      if (seconds < sevenDays) throw ctx.failed("Neon PITR retention is below seven days")
      return { compliant: true, project_id: payload.project.id, history_retention_seconds: seconds }
    }
    const projects = Array.isArray(payload) ? payload : []
    const targets = (scope.document.projects ?? []).filter((project) => project.status === "in_scope")
    const classified = new Set((scope.document.projects ?? []).map((project) => project.project_id))
    const missing = targets.some((target) => projects.filter((project) => project.id === target.project_id && project.name === target.project_name).length !== 1)
    const drifted = projects.some((project) => (project.name ?? "").startsWith("stllr-") && project.id && !classified.has(project.id))
    if (missing || drifted) throw ctx.blocked("Neon evidence collection blocked")
    const minimized = targets.map((target) => {
      const project = projects.find((item) => item.id === target.project_id)
      return {
        project_id: project?.id,
        project_name: project?.name,
        region_id: project?.region_id,
        history_retention_seconds: project?.history_retention_seconds,
      }
    })
    const mismatched = targets.filter((target) => {
      const project = projects.find((item) => item.id === target.project_id)
      return project?.history_retention_seconds !== (target.history_retention_seconds ?? sevenDays)
    })
    if (mismatched.length > 0) throw ctx.failed("Neon PITR retention does not match the approved state", { projects: mismatched.map((project) => project.project_name) })
    return { compliant: true, scope_digest: scope.digest, target_count: minimized.length, projects: minimized }
  },
})

async function readPayload<T>(ctx: CheckContext): Promise<T> {
  if (ctx.clients.payload) return await ctx.clients.payload(ctx.recipeId) as T
  const scope = await ctx.scope<{ org_id?: string }>(ctx.binding.scope)
  const orgID = scope.document.org_id
  if (!orgID) throw ctx.blocked("Neon scope is missing org_id")
  const response = await fetch(`https://console.neon.tech/api/v2/projects?org_id=${encodeURIComponent(orgID)}`, {
    headers: { authorization: `Bearer ${ctx.secret("NEON_API_KEY")}`, accept: "application/json" },
  })
  if (!response.ok) throw ctx.blocked("Neon API request failed", { status: response.status })
  const body = await response.json() as { projects?: NeonProject[] }
  return (body.projects ?? []) as T
}
