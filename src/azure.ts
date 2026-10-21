import { defineCheck } from "./define.ts"
import { providerPayload } from "./read.ts"
import type { Check, CheckContext } from "./types.ts"

type InboxScope = {
  primary_address: string
  published_address: string
  recipient_type: string
  full_access: string[]
  delivery_subject_marker: string
  delivery_max_age_days: number
  sender_domain_denylist: string[]
}

type InboxPayload = {
  graph_mails?: string[]
  primary?: string
  recipient_type?: string
  addresses?: string[]
  permissions?: Array<{ user: string; rights: string[]; deny: boolean }>
  traces?: Array<{ received?: string; sender_domain?: string; recipient?: string; status?: string; subject_has_marker?: boolean }>
}

export const securityInbox: Check = defineCheck({
  id: "azure.security-inbox",
  secrets: ["AZURE_ACCESS_TOKEN", "AZURE_TENANT_ID"],
  scopeKind: "fedramp_security_inbox",
  async run(ctx) {
    const scope = await ctx.scope<InboxScope>(ctx.binding.scope)
    const document = scope.document
    const doc = await providerPayload<InboxPayload>(ctx, () => {
      const azure = ctx.clients.azure?.(ctx.secret("AZURE_ACCESS_TOKEN"))
      if (!azure) throw ctx.blocked("azure security inbox client is not configured")
      const since = new Date(ctx.now.getTime() - document.delivery_max_age_days * 86400 * 1000)
      return azure.inbox({
        tenant: ctx.secret("AZURE_TENANT_ID"),
        primary: document.primary_address,
        marker: document.delivery_subject_marker,
        since: since.toISOString(),
        until: ctx.now.toISOString(),
      })
    })
    const holders = unique((doc.graph_mails ?? []).map((mail) => mail.toLowerCase()))
    const published = document.published_address.toLowerCase()
    const primary = document.primary_address.toLowerCase()
    const alias = (doc.addresses ?? []).some((address) => address.toLowerCase() === `smtp:${published}`)
    const access = unique((doc.permissions ?? [])
      .filter((item) => !item.deny && item.rights.includes("FullAccess"))
      .map((item) => item.user.toLowerCase())
      .filter((user) => user !== "nt authority\\self"))
    const expected = unique(document.full_access.map((user) => user.toLowerCase()))
    if (holders.join() !== primary || !alias || (doc.primary ?? "").toLowerCase() !== primary) throw ctx.failed("fedramp security inbox address is not on the shared mailbox")
    if (doc.recipient_type !== document.recipient_type) throw ctx.failed("fedramp security inbox is not a shared mailbox")
    if (access.join() !== expected.join()) throw ctx.failed("fedramp security inbox full access does not match the scope")
    const now = ctx.now.getTime()
    const windowMs = document.delivery_max_age_days * 86400 * 1000
    const denied = new Set(document.sender_domain_denylist.map((item) => item.toLowerCase()))
    const marked = (doc.traces ?? []).filter((trace) => trace.subject_has_marker && [published, primary].includes((trace.recipient ?? "").toLowerCase()))
    const fresh = marked.filter((trace) => {
      const at = Date.parse(trace.received ?? "")
      return trace.status === "Delivered" && !Number.isNaN(at) && now - at <= windowMs && at <= now
    })
    const external = fresh.filter((trace) => {
      const domain = (trace.sender_domain ?? "").toLowerCase()
      return domain.length > 0 && !denied.has(domain)
    })
    if (external.length > 0) {
      const delivery = external.sort((a, b) => Date.parse(a.received ?? "") - Date.parse(b.received ?? ""))[external.length - 1]
      return {
        compliant: true,
        scope_digest: scope.digest,
        primary_address: document.primary_address,
        published_address: document.published_address,
        recipient_type: document.recipient_type,
        full_access: expected,
        delivery: { received: new Date(Date.parse(delivery.received ?? "")).toISOString().replace(".000Z", "Z"), sender_domain: (delivery.sender_domain ?? "").toLowerCase(), status: "Delivered" },
      }
    }
    if (fresh.some((trace) => denied.has((trace.sender_domain ?? "").toLowerCase()))) throw ctx.failed("fedramp security inbox test message was not external")
    const row = await ctx.store.current(ctx.recipeId, "send")
    if (row && Date.parse(row.deadline) > now) throw ctx.pending(row.windowId)
    throw ctx.failed("fedramp security inbox has no recent delivered test message")
  },
})

export const offeringInventory: Check = defineCheck({
  id: "azure.offering-inventory",
  secrets: ["AZURE_ACCESS_TOKEN"],
  scopeKind: "azure_offering_scope",
  async run(ctx) {
    const scope = await ctx.scope<AzureScope>(ctx.binding.scope)
    const live = await providerPayload<AzureLive>(ctx, () => {
      const azure = ctx.clients.azure?.(ctx.secret("AZURE_ACCESS_TOKEN"))
      if (!azure) throw ctx.blocked("azure client is not configured")
      return azure.offering()
    })
    for (const [key, names] of [
      ["key_vaults", namesOf(live.key_vaults)],
      ["storage_accounts", namesOf(live.storage_accounts)],
    ] as const) {
      const classified = new Set((scope.document[key] as Array<{ name: string }>).map((item) => item.name))
      if (names.some((name) => !classified.has(name))) throw ctx.blocked("Azure offering inventory does not match the approved scope")
    }
    const vault = scope.document.key_vaults.find((item) => item.status === "in_scope")
    const hub = scope.document.event_hubs.find((item) => item.status === "in_scope")
    const account = scope.document.storage_accounts.find((item) => item.status === "in_scope")
    const container = scope.document.containers.find((item) => item.status === "in_scope" && item.account === account?.name)
    return {
      compliant: true,
      scope_digest: scope.digest,
      subscription: scope.document.subscription_name,
      key_vault: vault ? { name: vault.name, network_default_action: vault.network_default_action } : undefined,
      event_hub: hub ? { name: hub.name } : undefined,
      consumer_groups: scope.document.consumer_groups.filter((item) => item.status === "in_scope").map((item) => item.name),
      storage_accounts: account ? [{ name: account.name, containers: container ? [{ immutability_days: container.immutability_days }] : [] }] : [],
      workspace: { name: scope.document.workspaces.find((item) => item.status === "in_scope")?.name },
      excluded_storage_account_count: scope.document.storage_accounts.filter((item) => item.status === "excluded").length,
    }
  },
})

export const keyVaultAudit: Check = defineCheck({
  id: "azure.key-vault-audit",
  secrets: ["AZURE_ACCESS_TOKEN"],
  scopeKind: "azure_offering_scope",
  async run(ctx) {
    const scope = await ctx.scope<AzureScope>(ctx.binding.scope)
    const live = await providerPayload<{ vaults: Array<{ name: string; settings?: Array<{ workspace?: string | null; event_hub_namespace?: string; logs?: Array<{ category?: string | null; categoryGroup?: string; enabled?: boolean }> }> }> }>(ctx, () => {
      const azure = ctx.clients.azure?.(ctx.secret("AZURE_ACCESS_TOKEN"))
      if (!azure) throw ctx.blocked("azure client is not configured")
      return azure.keyVaultAudit()
    })
    const required = new Set(scope.document.key_vaults.filter((item) => item.status === "in_scope").map((item) => item.name))
    const approvedWorkspaces = new Set(scope.document.workspaces.filter((item) => item.status === "in_scope").map((item) => item.name))
    const approvedHubs = new Set(scope.document.event_hub_namespaces.filter((item) => item.status === "in_scope").map((item) => item.name))
    const present = new Set(live.vaults.map((vault) => vault.name))
    if ([...required].some((name) => !present.has(name))) throw ctx.failed("in-scope key vault has no audit diagnostic setting")
    const vaults = live.vaults.filter((vault) => required.has(vault.name)).map((vault) => {
      const setting = (vault.settings ?? []).find((item) => (item.logs ?? []).some((log) => log.enabled && (log.category === "AuditEvent" || log.categoryGroup === "audit" || log.categoryGroup === "allLogs")))
      if (!setting) throw ctx.failed("in-scope key vault has no audit diagnostic setting")
      const workspace = setting.workspace && approvedWorkspaces.has(setting.workspace) ? setting.workspace : null
      const eventHub = setting.event_hub_namespace && approvedHubs.has(setting.event_hub_namespace) ? setting.event_hub_namespace : undefined
      if (!workspace && !eventHub) throw ctx.failed("in-scope key vault audit destination is not approved")
      return { name: vault.name, audit_event: true, workspace, event_hub_namespace: eventHub }
    })
    return { compliant: true, scope_digest: scope.digest, vault_count: vaults.length, vaults }
  },
})

type Named = { name: string; status: string }
type AzureScope = {
  subscription_name: string
  key_vaults: Array<Named & { network_default_action?: string }>
  event_hub_namespaces: Named[]
  event_hubs: Array<Named>
  consumer_groups: Named[]
  storage_accounts: Named[]
  containers: Array<{ account: string; name: string; status: string; immutability_days?: number }>
  workspaces: Named[]
}
type AzureLive = { key_vaults: Array<{ name: string }>; storage_accounts: Array<{ name: string }> }

function namesOf(items: Array<{ name: string }> | undefined) {
  return (items ?? []).map((item) => item.name)
}

function unique(values: string[]) {
  return [...new Set(values)].sort()
}

