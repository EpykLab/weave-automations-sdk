import assert from "node:assert/strict"
import test from "node:test"
import { securityInbox } from "../src/azure.ts"
import { appDatabase, logShip, reportJob, signin } from "../src/kubernetes.ts"
import { azureClient } from "../src/providers.ts"
import { context, readJSON } from "./helpers.ts"

test("azure inbox keeps the delivery and drops mailbox secrets", async () => {
  const scope = await readJSON("fedramp-security-inbox.json")
  const graph = await readJSON("fedramp-inbox/graph.json")
  const mailbox = await readJSON("fedramp-inbox/mailbox.json")
  const permissions = await readJSON("fedramp-inbox/permissions.json")
  const trace = await readJSON("fedramp-inbox/trace.json")
  const result = await securityInbox.run(context({
    scope,
    now: "2026-10-21T18:00:00Z",
    secret: { AZURE_ACCESS_TOKEN: "token", AZURE_TENANT_ID: "tenant" },
    clients: {
      payload: undefined,
      azure: () => azureClient("token", async (url) => {
        assert.equal(new URL(url).host, "graph.microsoft.com")
        return graph
      }, async (url, _headers, body) => {
        assert.equal(new URL(url).host, "outlook.office365.com")
        const command = (body as { CmdletInput: { CmdletName: string } }).CmdletInput.CmdletName
        if (command === "Get-Mailbox") return mailbox
        if (command === "Get-MailboxPermission") return permissions
        if (command === "Get-MessageTrace") return trace
        throw new Error(command)
      }),
    },
  })) as { delivery: { sender_domain: string; status: string } }
  assert.equal(result.delivery.sender_domain, "example.com")
  assert.equal(result.delivery.status, "Delivered")
  const encoded = JSON.stringify(result)
  assert.equal(encoded.includes("secret"), false)
  assert.equal(encoded.includes("hidden"), false)
})

test("a pooled database secret is counted without its password", async () => {
  const password = "secret-password"
  const result = await appDatabase.run(context({
    scope: {},
    clients: {
      payload: undefined,
      kubernetes: () => ({
        async get(path) {
          if (path === "/api/v1/namespaces") return { items: [{ metadata: { name: "tenant-example" } }] }
          if (path === "/api/v1/namespaces/tenant-example/secrets") {
            return { items: [{ data: { DATABASE_URL: Buffer.from(`postgresql://user:${password}@ep-secret-pooler.example.neon.tech/app?sslmode=require`).toString("base64") } }] }
          }
          throw new Error(path)
        },
      }),
    },
  })) as { pooled_count: number; tls_required: boolean }
  assert.equal(result.pooled_count, 1)
  assert.equal(result.tls_required, true)
  assert.equal(JSON.stringify(result).includes(password), false)
})

test("report and sign-in env names come from secret refs", async () => {
  const deployment = {
    metadata: { namespace: "tenant-example" },
    spec: { template: { spec: { containers: [{ env: [
      { name: "RESEND_API_KEY", valueFrom: { secretKeyRef: { name: "tenant-secrets", key: "RESEND_API_KEY" } } },
      { name: "AWS_ACCESS_KEY_ID", valueFrom: { secretKeyRef: { name: "tenant-secrets", key: "STLLR_AWS_ACCESS_KEY_ID" } } },
      { name: "AWS_SECRET_ACCESS_KEY", valueFrom: { secretKeyRef: { name: "tenant-secrets", key: "STLLR_AWS_SECRET_ACCESS_KEY" } } },
      { name: "STLLR_AUTH0_OIDC_ISSUER", valueFrom: { secretKeyRef: { name: "tenant-secrets", key: "STLLR_AUTH0_OIDC_ISSUER" } } },
      { name: "STLLR_REDIS_CONN_STRING", valueFrom: { secretKeyRef: { name: "tenant-secrets", key: "STLLR_REDIS_CONN_STRING" } } },
      { name: "REPORT_BUCKET", value: "coc-reports" },
    ] }] } } },
  }
  const kube = () => ({
    async get(path: string) {
      if (path === "/apis/apps/v1/deployments") return { items: [deployment] }
      return { items: [] }
    },
  })
  const report = await reportJob.run(context({ scope: {}, clients: { payload: undefined, kubernetes: kube } })) as { email_key_mounted: boolean; bucket_override_mounted: boolean }
  assert.equal(report.email_key_mounted, true)
  assert.equal(report.bucket_override_mounted, true)
  assert.equal(JSON.stringify(report).includes("secret-resend"), false)
  const login = await signin.run(context({
    scope: { apps: [{ hostname: "login.example", status: "in_scope" }] },
    clients: {
      payload: undefined,
      kubernetes: kube,
      tls: () => ({ async sample() { return { hosts: [{ name: "login.example", protocol: "TLSv1.3", cipher: "TLS_AES_256_GCM_SHA384", verification: "OK", issuer: "Let's Encrypt", not_after: "2027-01-01T00:00:00Z", http_status: 200 }] } } }),
    },
  })) as { auth0_issuer_mounted: boolean; cache_connection_mounted: boolean }
  assert.equal(login.auth0_issuer_mounted, true)
  assert.equal(login.cache_connection_mounted, true)
})

test("log shipping reads the vector service and the elasticsearch config", async () => {
  const config = "sinks:\n  elastic_cloud:\n    type: elasticsearch\n    endpoints:\n      - https://example.es.example.elastic.cloud\n    api_version: v8\n    request:\n      headers:\n        Authorization: ApiKey secret-elastic-key\n"
  const result = await logShip.run(context({
    scope: {},
    clients: {
      payload: undefined,
      kubernetes: () => ({
        async get(path) {
          if (path === "/api/v1/namespaces") return { items: [{ metadata: { name: "tenant-example" } }] }
          if (path.endsWith("/configmaps")) return { items: [{ data: { vector: config } }] }
          if (path.endsWith("/services")) return { items: [{ metadata: { name: "other" }, spec: { ports: [{ port: 80 }] } }, { metadata: { name: "vector" }, spec: { ports: [{ port: 8181 }, { port: 8182 }] } }] }
          throw new Error(path)
        },
      }),
    },
  })) as { sink_type: string; app_log_port: number; api_key_mounted: boolean }
  assert.equal(result.sink_type, "elasticsearch")
  assert.equal(result.app_log_port, 8181)
  assert.equal(result.api_key_mounted, true)
  assert.equal(JSON.stringify(result).includes("secret-elastic-key"), false)
})
