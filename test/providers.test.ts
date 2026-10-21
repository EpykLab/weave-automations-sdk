import assert from "node:assert/strict"
import test from "node:test"
import { auth0 } from "../src/inventory.ts"
import { auth0Client, azureClient, cloudflareClient, digitaloceanClient, elasticClient, parseKubeconfig, resendClient, signS3, tigrisClient } from "../src/providers.ts"
import { memoryStore } from "../src/store.ts"
import { CheckError, type CheckContext } from "../src/types.ts"

test("provider clients keep inventory fields and drop credentials", async () => {
  const auth = await auth0Client("token", async (url) => {
    assert.equal(new URL(url).host, "example.auth0.com")
    return url.includes("organizations")
      ? [{ name: "mccutdotus", display_name: "mccut.us", id: "org-secret" }]
      : [{ name: "Tenant Login", client_id: "secret-client" }]
  }).inventory("example.auth0.com")
  assert.deepEqual(auth, { organizations: [{ name: "mccutdotus", display_name: "mccut.us" }], applications: [{ name: "Tenant Login" }] })
  assert.equal(JSON.stringify(auth).includes("secret"), false)

  const zones = await cloudflareClient("token", async (url) => {
    if (url.includes("/dns_records")) return { success: true, result: [{ name: "login.example", type: "TXT", content: "secret-token" }], result_info: { total_pages: 1 } }
    return { success: true, result: [{ id: "zone-1", name: "example.com" }], result_info: { total_pages: 1 } }
  }).inventory()
  assert.deepEqual(zones.records, [{ name: "login.example", type: "TXT" }])
  assert.equal(JSON.stringify(zones).includes("secret-token"), false)

  const databases = await digitaloceanClient("token", async () => ({ databases: [{ name: "cache", engine: "valkey", status: "online", region: "sfo3", connection: { uri: "rediss://secret" } }] })).databases()
  assert.deepEqual(databases, [{ name: "cache", engine: "valkey", status: "online", region: "sfo3" }])

  const elastic = await elasticClient("key", async (url) => url.endsWith("/security") ? { items: [{ name: "siem", cloud_id: "secret" }] } : { items: [] }).projects()
  assert.deepEqual(elastic.projects, [{ name: "siem" }])

  const resend = await resendClient("token", async () => ({ data: [{ name: "mail.example", id: "secret-id", token: "secret-token" }] })).inventory()
  assert.deepEqual(resend.api_keys, [{ name: "mail.example" }])
  assert.equal(JSON.stringify(resend).includes("secret"), false)
})

test("azure audit keeps the approved workspace name", async () => {
  const audit = await azureClient("token", async (url) => {
    if (url.endsWith("/subscriptions?api-version=2022-12-01")) return { value: [{ subscriptionId: "sub" }] }
    if (url.includes("/vaults?")) return { value: [{ name: "app", id: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/app" }] }
    return { value: [{ workspaceId: "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/central", logs: [{ category: "AuditEvent", enabled: true }] }] }
  }).keyVaultAudit()
  assert.equal(audit.vaults[0].settings[0].workspace, "central")
  assert.equal(audit.vaults[0].settings[0].logs[0].enabled, true)
})

test("tigris bucket names come from the list response", async () => {
  const buckets = await tigrisClient("access", "secret", async (url) => {
    assert.equal(url, "https://t3.storage.dev/")
    return "<ListAllMyBucketsResult><Buckets><Bucket><Name>coc-reports</Name></Bucket></Buckets></ListAllMyBucketsResult>"
  }).buckets()
  assert.deepEqual(buckets, [{ name: "coc-reports" }])
  const header = signS3({ method: "GET", url: "https://t3.storage.dev/", accessKey: "access", secretKey: "secret", now: new Date("2026-10-21T00:00:00Z"), region: "auto", service: "s3" })
  assert.match(header.authorization, /^AWS4-HMAC-SHA256 Credential=access\/20261021\/auto\/s3\/aws4_request/)
})

test("a kubeconfig token is read without printing it", () => {
  const config = parseKubeconfig("clusters:\n- cluster:\n    server: https://cluster.example\nusers:\n- user:\n    token: secret-token\n")
  assert.equal(config.server, "https://cluster.example")
  assert.equal(config.token, "secret-token")
})

test("auth0 inventory uses the client when no fixture payload is configured", async () => {
  const result = await auth0.run(context()) as { organizations: Array<{ name: string }> }
  assert.deepEqual(result.organizations, [{ name: "mccutdotus", display_name: "mccut.us" }])
})

function context(): CheckContext {
  return {
    recipeId: "auth0-tenant-inventory",
    binding: { scope: "evidence/scope/auth0-tenant.json" },
    now: new Date("2026-10-21T00:00:00Z"),
    secret: () => "token",
    store: memoryStore(new Date("2026-10-21T00:00:00Z")),
    http: { async get() { throw new Error("unused") } },
    clients: {
      github: () => { throw new Error("unused") },
      auth0: () => ({
        async inventory() {
          return { organizations: [{ name: "mccutdotus", display_name: "mccut.us" }], applications: [{ name: "Login" }] }
        },
      }),
    },
    async scope() {
      return {
        document: {
          tenant: "example.auth0.com",
          organizations: [{ name: "mccutdotus", display_name: "mccut.us", status: "in_scope" }],
          applications: [{ name: "Login", status: "in_scope" }],
        } as never,
        digest: "digest",
      }
    },
    blocked: (message, detail) => new CheckError(message, "blocked", detail),
    failed: (message, detail) => new CheckError(message, "failed", detail),
    pending: (windowId) => new CheckError("pending", "pending", windowId),
  }
}
