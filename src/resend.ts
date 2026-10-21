import { defineAction, defineCheck } from "./define.ts"
import { providerPayload } from "./read.ts"
import type { Action, Check, CheckContext } from "./types.ts"

const week = 7 * 24 * 60 * 60 * 1000

type InboxScope = {
  published_address: string
  delivery_subject_marker: string
  sender_domain_denylist: string[]
}

export const accountInventory: Check = defineCheck({
  id: "resend.account-inventory",
  secrets: ["RESEND_API_KEY"],
  scopeKind: "resend_account_scope",
  async run(ctx) {
    const scope = await ctx.scope<{
      domains: Array<{ name: string; domain_status: string; region: string; status: string }>
      api_keys: Array<{ name: string; status: string }>
    }>(ctx.binding.scope)
    const payload = await providerPayload<{ domains: Array<{ name: string }>; api_keys: Array<{ name: string; token?: string; id?: string }> }>(ctx, () => {
      const resend = ctx.clients.resend?.(ctx.secret("RESEND_API_KEY"))
      if (!resend) throw ctx.blocked("resend client is not configured")
      return resend.inventory()
    })
    const domainNames = new Set(scope.document.domains.map((item) => item.name))
    const keyNames = new Set(scope.document.api_keys.map((item) => item.name))
    if (payload.domains.some((item) => !domainNames.has(item.name)) || payload.api_keys.some((item) => !keyNames.has(item.name))) {
      throw ctx.blocked("Resend account inventory does not match the approved scope")
    }
    return {
      compliant: true,
      scope_digest: scope.digest,
      domains: scope.document.domains.filter((item) => item.status === "in_scope").map((item) => ({ name: item.name, domain_status: item.domain_status, region: item.region })),
      api_keys: scope.document.api_keys.filter((item) => item.status === "in_scope").map((item) => item.name),
      excluded_api_key_count: scope.document.api_keys.filter((item) => item.status === "excluded").length,
    }
  },
})

export const deliveryTest: Action = defineAction({
  id: "resend.delivery-test",
  secrets: ["RESEND_API_KEY", "RESEND_FROM"],
  scopeKind: "fedramp_security_inbox",
  async run(ctx) {
    const scope = await ctx.scope<InboxScope>(ctx.binding.scope)
    const from = ctx.secret("RESEND_FROM")
    const domain = from.split("@")[1]?.toLowerCase() ?? ""
    if (scope.document.sender_domain_denylist.map((item) => item.toLowerCase()).includes(domain)) {
      throw ctx.failed("sender domain is on the denylist")
    }
    const windowId = ctx.store.window(ctx.recipeId, "send", week)
    const existing = await ctx.store.current(ctx.recipeId, "send")
    if (existing?.windowId === windowId) return { window_id: windowId, retry: { budget_ms: 300_000, initial_ms: 2_000, max_interval_ms: 30_000 } }
    const deadline = new Date(ctx.now.getTime() + 300_000).toISOString()
    await ctx.store.put({ recipeId: ctx.recipeId, action: "send", windowId, status: "accepted", deadline })
    const client = ctx.clients.resend?.(ctx.secret("RESEND_API_KEY"))
    if (!client) throw ctx.blocked("resend client is not configured")
    await client.send({
      from,
      to: scope.document.published_address,
      subject: scope.document.delivery_subject_marker,
      idempotencyKey: `${ctx.recipeId}:${windowId}`,
    })
    return { window_id: windowId, retry: { budget_ms: 300_000, initial_ms: 2_000, max_interval_ms: 30_000 } }
  },
})

