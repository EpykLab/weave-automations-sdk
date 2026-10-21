import assert from "node:assert/strict"
import test from "node:test"
import { offeringInventory, keyVaultAudit, securityInbox } from "../src/azure.ts"
import { auth0, cloudflare, elastic, flyApps, flyCerts, tigris, tls, valkey } from "../src/inventory.ts"
import { appDatabase, logShip, namespaces, networkIsolation, posture, reportJob, signin, workloads } from "../src/kubernetes.ts"
import { backupPosture } from "../src/neon.ts"
import { probe } from "../src/registry.ts"
import { accountInventory, deliveryTest } from "../src/resend.ts"
import { CheckError } from "../src/types.ts"
import { context, readJSON } from "./helpers.ts"

test("registry resolves inventory, cluster, and inbox probes", () => {
  assert.deepEqual(probe("cloudflare.dns-zone")?.secrets, ["CLOUDFLARE_API_TOKEN"])
  assert.deepEqual(probe("kubernetes.posture")?.secrets, ["KUBECONFIG"])
  assert.equal(probe("azure.security-inbox")?.id, "azure.security-inbox")
  assert.equal(probe("resend.delivery-test")?.id, "resend.delivery-test")
  assert.equal(probe("repository-control-tests"), undefined)
})

test("neon history below seven days returns no observation", async () => {
  const payload = await readJSON("neon-project-pitr-insufficient.json")
  await assert.rejects(
    () => backupPosture.run(context({ scope: { projects: [] }, payload })),
    (error: unknown) => error instanceof CheckError && error.kind === "failed",
  )
})

test("neon history of seven days returns the minimized project", async () => {
  const payload = await readJSON("neon-project-pitr-enabled.json")
  const result = await backupPosture.run(context({ scope: { projects: [] }, payload }))
  assert.deepEqual(result, { compliant: true, project_id: "example", history_retention_seconds: 604800 })
  assert.equal(JSON.stringify(result).includes("postgresql://"), false)
})

test("a fresh external inbox delivery is minimized", async () => {
  const scope = await readJSON("fedramp-security-inbox.json")
  const payload = await readJSON("fedramp-inbox/normalized.json")
  const result = await securityInbox.run(context({ scope, payload, now: "2026-10-21T18:00:00Z" })) as { delivery: { sender_domain: string; status: string }; full_access: string[] }
  assert.equal(result.delivery.sender_domain, "example.com")
  assert.equal(result.delivery.status, "Delivered")
  assert.deepEqual(result.full_access, ["dhoenisch@epyklab.com", "mchapman@epyklab.com"])
  assert.equal(JSON.stringify(result).includes("hidden"), false)
})

test("a missing inbox delivery is not an observation", async () => {
  const scope = await readJSON("fedramp-security-inbox.json")
  const payload = await readJSON<Record<string, unknown>>("fedramp-inbox/normalized.json")
  payload.traces = []
  await assert.rejects(() => securityInbox.run(context({ scope, payload })), (error: unknown) => error instanceof CheckError && error.kind === "failed")
})

test("an internal inbox sender is rejected", async () => {
  const scope = await readJSON("fedramp-security-inbox.json")
  const payload = await readJSON<{ traces: Array<{ sender_domain: string }> }>("fedramp-inbox/normalized.json")
  payload.traces[0].sender_domain = "epyklab.com"
  await assert.rejects(() => securityInbox.run(context({ scope, payload, now: "2026-10-21T18:00:00Z" })), /not external/)
})

test("resend writes the window before sending and sends once", async () => {
  const scope = await readJSON("fedramp-security-inbox.json")
  const sends: string[] = []
  const order: string[] = []
  const ctx = context({
    scope,
    secret: { RESEND_FROM: "inbox@external.test", RESEND_API_KEY: "key" },
    clients: {
      resend: () => ({
        async send(message) {
          order.push("send")
          sends.push(message.idempotencyKey)
        },
      }),
    },
  })
  const original = ctx.store.put.bind(ctx.store)
  ctx.store.put = async (row) => {
    order.push("put")
    return original(row)
  }
  await deliveryTest.run(ctx)
  await deliveryTest.run(ctx)
  assert.deepEqual(order, ["put", "send"])
  assert.equal(sends.length, 1)
  assert.match(sends[0], /^fixture:2026-10-15T00:00:00Z$/)
})

test("an internal resend sender fails before send", async () => {
  const scope = await readJSON("fedramp-security-inbox.json")
  let sent = false
  const ctx = context({
    scope,
    secret: { RESEND_FROM: "alerts@epyklab.com" },
    clients: { resend: () => ({ async send() { sent = true } }) },
  })
  await assert.rejects(() => deliveryTest.run(ctx), /denylist/)
  assert.equal(sent, false)
})

async function passes(check: { run(ctx: ReturnType<typeof context>): Promise<unknown> }, scopeFile: string, payloadFile: string) {
  return check.run(context({ scope: await readJSON(scopeFile), payload: await readJSON(payloadFile) }))
}

test("auth0 inventory drops client ids and excluded apps", async () => {
  const result = await passes(auth0, "mas/auth0-scope.json", "mas/auth0-inventory.json") as { tenant: string; applications: string[] }
  assert.equal(result.tenant, "example.auth0.com")
  assert.deepEqual(result.applications, ["Stellarbridge Tenant Login (prod)"])
  assert.equal(JSON.stringify(result).includes("secret-client-id"), false)
  const extra = await readJSON<{ organizations: Array<{ name: string; display_name: string }> }>("mas/auth0-inventory.json")
  extra.organizations.push({ name: "other", display_name: "Other" })
  const auth0Scope = await readJSON("mas/auth0-scope.json")
  await assert.rejects(() => auth0.run(context({ scope: auth0Scope, payload: extra })))
})

test("cloudflare inventory keeps counts and drops record contents", async () => {
  const result = await passes(cloudflare, "mas/cf-scope.json", "mas/cf-inventory.json") as { zone: { name: string }; excluded_zone_count: number; required_record_count: number; txt_record_count: number }
  assert.equal(result.zone.name, "stellarbridge.app")
  assert.equal(result.excluded_zone_count, 1)
  assert.equal(result.required_record_count, 1)
  assert.equal(result.txt_record_count, 1)
  assert.equal(JSON.stringify(result).includes("secret-dns-token"), false)
  assert.equal(JSON.stringify(result).includes("login.stellarbridge.app"), false)
})

test("valkey inventory drops the connection uri", async () => {
  const result = await passes(valkey, "mas/do-scope.json", "mas/do-databases.json") as { databases: Array<{ name: string }> }
  assert.deepEqual(result.databases, [{ name: "stllr-k8s-mccutdotus", engine: "valkey", status: "online", region: "sfo3" }])
  assert.equal(JSON.stringify(result).includes("rediss://"), false)
})

test("fly apps and certs are minimized", async () => {
  const apps = await passes(flyApps, "mas/fly-scope.json", "mas/fly-apps.json") as { apps: Array<{ status: string }> }
  assert.equal(apps.apps.length, 2)
  assert.equal(apps.apps[0].status, "deployed")
  assert.equal(JSON.stringify(apps).includes("fly-secret-value"), false)
  const certs = await passes(flyCerts, "mas/fly-scope.json", "mas/fly-certs.json") as { certificates: Array<{ hostname: string; status: string }> }
  assert.equal(certs.certificates[0].hostname, "login.stellarbridge.app")
  assert.equal(certs.certificates[0].status, "Ready")
  assert.equal(JSON.stringify(certs).includes("secret-cert"), false)
})

test("tigris, elastic, and resend inventories fail closed on an unclassified target", async () => {
  const buckets = await passes(tigris, "mas/tigris-scope.json", "mas/tigris-buckets.json") as { buckets: string[]; organization: string }
  assert.equal(buckets.organization, "example-org")
  assert.deepEqual(buckets.buckets, ["coc-reports"])
  const projects = await passes(elastic, "mas/elastic-scope.json", "mas/elastic-projects.json") as { projects: Array<{ name: string }> }
  assert.equal(projects.projects[0].name, "stellarbridge-siem")
  await assert.rejects(() => passes(elastic, "mas/elastic-scope.json", "mas/elastic-projects-extra.json"))
  const account = await passes(accountInventory, "mas/resend-scope.json", "mas/resend-inventory.json") as { api_keys: string[]; excluded_api_key_count: number }
  assert.deepEqual(account.api_keys, ["coc-sending"])
  assert.equal(account.excluded_api_key_count, 1)
  await assert.rejects(() => passes(accountInventory, "mas/resend-scope.json", "mas/resend-inventory-extra.json"))
})

test("azure offering inventory drops secret values", async () => {
  const result = await passes(offeringInventory, "mas/azure-scope.json", "mas/azure-inventory.json") as {
    subscription: string
    key_vault: { name: string; network_default_action: string }
    storage_accounts: Array<{ name: string; containers: Array<{ immutability_days: number }> }>
    excluded_storage_account_count: number
  }
  assert.equal(result.subscription, "example_sub")
  assert.equal(result.key_vault.network_default_action, "Deny")
  assert.equal(result.storage_accounts[0].containers[0].immutability_days, 2192)
  assert.equal(result.excluded_storage_account_count, 1)
  assert.equal(JSON.stringify(result).includes("secret-subscription-id"), false)
  await assert.rejects(() => passes(offeringInventory, "mas/azure-scope.json", "mas/azure-inventory-extra.json"))
})

test("key vault audit accepts the approved workspace and event hub", async () => {
  const workspace = await passes(keyVaultAudit, "azure-offering.json", "ksi/key-vault-audit.json") as { vaults: Array<{ name: string; workspace: string }> }
  assert.equal(workspace.vaults[0].name, "turnkey-prod-kv")
  assert.equal(workspace.vaults[0].workspace, "stllr-prod-audit-logs")
  const hub = await passes(keyVaultAudit, "azure-offering.json", "ksi/key-vault-audit-event-hub.json") as { vaults: Array<{ workspace: null; event_hub_namespace: string }> }
  assert.equal(hub.vaults[0].workspace, null)
  assert.equal(hub.vaults[0].event_hub_namespace, "stllr-prod-audit-events")
  await assert.rejects(() => passes(keyVaultAudit, "azure-offering.json", "ksi/key-vault-audit-missing.json"))
  await assert.rejects(() => passes(keyVaultAudit, "azure-offering.json", "ksi/key-vault-audit-unapproved.json"))
})

test("tls sample drops hostnames and keys", async () => {
  const result = await passes(tls, "mas/tenant-tls-scope.json", "mas/tenant-tls.json") as { protocols: string[]; sample_count: number }
  assert.deepEqual(result.protocols, ["TLSv1.3"])
  assert.equal(result.sample_count, 1)
  assert.equal(JSON.stringify(result).includes("tenant.example.com"), false)
  assert.equal(JSON.stringify(result).includes("secret-tls-key"), false)
  await assert.rejects(() => passes(tls, "mas/tenant-tls-scope.json", "mas/tenant-tls-weak.json"))
})

test("kubernetes posture matches the collector counts and fails the weak fixture", async () => {
  const passing = {
    workloads: await readJSON("k8s-posture/workloads.json"),
    namespaces: await readJSON("k8s-posture/namespaces.json"),
    policies: await readJSON("k8s-posture/network-policies.json"),
    services: await readJSON("k8s-posture/services.json"),
  }
  assert.deepEqual(await posture.run(context({ scope: {}, payload: passing })), {
    compliant: true,
    workloads: 1,
    containers: 1,
    namespaces: 2,
    network_policy_namespaces: 2,
    unexpected_public_services: 0,
  })
  const failing = {
    workloads: await readJSON("k8s-posture-failing/workloads.json"),
    namespaces: await readJSON("k8s-posture-failing/namespaces.json"),
    policies: await readJSON("k8s-posture-failing/network-policies.json"),
    services: await readJSON("k8s-posture-failing/services.json"),
  }
  await assert.rejects(() => posture.run(context({ scope: {}, payload: failing })))
})

test("namespace and workload inventories fail closed", async () => {
  const names = await passes(namespaces, "mas/aks-scope.json", "mas/aks-namespaces.json") as { required_namespaces: string[]; in_scope_namespaces: string[]; tenant_namespace_count: number }
  assert.deepEqual(names.required_namespaces, ["ingress-nginx"])
  assert.deepEqual(names.in_scope_namespaces, ["tenant-mccutdotus"])
  assert.equal(names.tenant_namespace_count, 2)
  await assert.rejects(() => passes(namespaces, "mas/aks-scope.json", "mas/aks-namespaces-unclassified.json"))
  const work = await passes(workloads, "mas/aks-scope.json", "mas/aks-deployments.json") as { missing_deployment_count: number; tenant_namespace_count: number }
  assert.equal(work.tenant_namespace_count, 1)
  assert.equal(work.missing_deployment_count, 0)
  await assert.rejects(() => passes(workloads, "mas/aks-scope.json", "mas/aks-deployments-missing.json"))
})

test("network isolation keeps tenant peers inside the allowed set", async () => {
  const result = await networkIsolation.run(context({
    scope: await readJSON("ksi/aks-scope.json"),
    payload: {
      namespaces: await readJSON("ksi/namespaces.json"),
      policies: await readJSON("ksi/network-policies.json"),
    },
  })) as { namespaces: Array<{ name: string; status: string; environment: string; policy_count: number; ingress_peer_namespaces: string[]; same_namespace_ingress: boolean; egress: boolean }> }
  assert.equal(result.namespaces.length, 6)
  const production = result.namespaces.find((item) => item.name === "tenant-mccutdotus")
  assert.equal(production?.status, "in_scope")
  assert.deepEqual(production?.ingress_peer_namespaces, ["caddy", "ingress-nginx"])
  assert.equal(production?.same_namespace_ingress, true)
  assert.equal(production?.egress, true)
  const policies = await readJSON<{ items: Array<{ metadata: { namespace: string }; spec: { ingress: Array<{ from: Array<{ namespace: string }> }> } }> }>("ksi/network-policies.json")
  policies.items.find((item) => item.metadata.namespace === "tenant-mccutdotus")!.spec.ingress[0].from[0].namespace = "tenant-preview"
  const isolationScope = await readJSON("ksi/aks-scope.json")
  const isolationNamespaces = await readJSON("ksi/namespaces.json")
  await assert.rejects(() => networkIsolation.run(context({
    scope: isolationScope,
    payload: { namespaces: isolationNamespaces, policies },
  })), /another tenant/)
})

test("connection checks minimize mounted configuration", async () => {
  const login = await signin.run(context({ scope: await readJSON("mas/connection-fly.json"), payload: await readJSON("mas/signin-connection.json") })) as { login_host: string; protocol: string }
  assert.equal(login.login_host, "login.example.test")
  assert.equal(login.protocol, "TLSv1.3")
  assert.equal(JSON.stringify(login).includes("secret-password"), false)
  const flyScope = await readJSON("mas/connection-fly.json")
  const weakSignin = await readJSON("mas/signin-connection-weak.json")
  await assert.rejects(() => signin.run(context({ scope: flyScope, payload: weakSignin })))
  const database = await appDatabase.run(context({ scope: {}, payload: await readJSON("mas/database-connection.json") })) as { pooled_count: number; direct_count: number; port: number; tls_required: boolean }
  assert.equal(database.pooled_count, 1)
  assert.equal(database.direct_count, 0)
  assert.equal(database.port, 5432)
  assert.equal(database.tls_required, true)
  assert.equal(JSON.stringify(database).includes("secret-password"), false)
  const mismatch = await readJSON("mas/database-connection-mismatch.json")
  await assert.rejects(() => appDatabase.run(context({ scope: {}, payload: mismatch })))
  const report = await reportJob.run(context({ scope: {}, payload: await readJSON("mas/report-connection.json") })) as { email_key_mounted: boolean }
  assert.equal(report.email_key_mounted, true)
  assert.equal(JSON.stringify(report).includes("secret-resend-token"), false)
  const missingReport = await readJSON("mas/report-connection-missing.json")
  await assert.rejects(() => reportJob.run(context({ scope: {}, payload: missingReport })))
  const logs = await logShip.run(context({ scope: {}, payload: await readJSON("mas/log-ship-connection.json") })) as { sink_type: string; app_log_port: number }
  assert.equal(logs.sink_type, "elasticsearch")
  assert.equal(logs.app_log_port, 8181)
  assert.equal(JSON.stringify(logs).includes("secret-elastic-key"), false)
  const weakLogs = await readJSON("mas/log-ship-connection-weak.json")
  await assert.rejects(() => logShip.run(context({ scope: {}, payload: weakLogs })))
})
