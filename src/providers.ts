import { createHash, createHmac } from "node:crypto"
import https from "node:https"
import tls from "node:tls"
import { githubClient } from "./github-client.ts"
import { CheckError, type Clients } from "./types.ts"

type FetchJSON = (url: string, headers: Record<string, string>) => Promise<unknown>

export function defaultClients(): Clients {
  return {
    github: githubClient,
    resend: resendClient,
    auth0: auth0Client,
    cloudflare: cloudflareClient,
    digitalocean: digitaloceanClient,
    fly: flyClient,
    tigris: tigrisClient,
    elastic: elasticClient,
    azure: azureClient,
    kubernetes: kubernetesClient,
    tls: tlsClient,
  }
}

export async function getJSON(url: string, headers: Record<string, string>, fetchJSON: FetchJSON = defaultFetch): Promise<unknown> {
  return fetchJSON(url, headers)
}

async function defaultFetch(url: string, headers: Record<string, string>) {
  const response = await fetch(url, { headers: { accept: "application/json", ...headers } })
  if (response.status === 401 || response.status === 403) throw new CheckError(`${new URL(url).host} returned ${response.status}`, "blocked", { status: response.status })
  if (!response.ok) throw new Error(`${new URL(url).host} returned ${response.status}`)
  return response.json() as Promise<unknown>
}

function bearer(token: string) {
  return { authorization: `Bearer ${token}` }
}

async function collectPages(start: string, headers: Record<string, string>, fetchJSON: FetchJSON, items: (body: unknown) => unknown[], next: (body: unknown) => string | undefined) {
  const all: unknown[] = []
  let url: string | undefined = start
  while (url) {
    const body = await fetchJSON(url, headers)
    all.push(...items(body))
    url = next(body)
  }
  return all
}

export function auth0Client(token: string, fetchJSON: FetchJSON = defaultFetch) {
  return {
    async inventory(tenant: string) {
      const organizations = await auth0Pages(`https://${tenant}/api/v2/organizations`, token, fetchJSON, "organizations")
      const applications = await auth0Pages(`https://${tenant}/api/v2/clients`, token, fetchJSON, "clients")
      return {
        organizations: organizations.map((item) => ({ name: text(item, "name"), display_name: text(item, "display_name") })),
        applications: applications.map((item) => ({ name: text(item, "name") })),
      }
    },
  }
}

async function auth0Pages(root: string, token: string, fetchJSON: FetchJSON, key: string) {
  const items: unknown[] = []
  for (let page = 0; page < 50; page += 1) {
    const body = await fetchJSON(`${root}?per_page=100&page=${page}`, bearer(token))
    const rows = Array.isArray(body) ? body : array(body, key)
    items.push(...rows)
    const doc = body as { total?: number; limit?: number; start?: number }
    if (rows.length < 100 || (doc.total !== undefined && (doc.start ?? 0) + (doc.limit ?? rows.length) >= doc.total)) break
  }
  return items
}

export function cloudflareClient(token: string, fetchJSON: FetchJSON = defaultFetch) {
  return {
    async inventory() {
      const zones = await cfList("https://api.cloudflare.com/client/v4/zones?per_page=50", token, fetchJSON)
      const records = []
      for (const zone of zones) {
        const id = text(zone, "id")
        const page = await cfList(`https://api.cloudflare.com/client/v4/zones/${id}/dns_records?per_page=100`, token, fetchJSON)
        records.push(...page.map((record) => ({ name: text(record, "name"), type: text(record, "type") })))
      }
      return { zones: zones.map((zone) => ({ name: text(zone, "name") })), records }
    },
  }
}

export function digitaloceanClient(token: string, fetchJSON: FetchJSON = defaultFetch) {
  return {
    async databases() {
      const rows = await collectPages("https://api.digitalocean.com/v2/databases?per_page=100", bearer(token), fetchJSON, (body) => array(body, "databases"), (body) => {
        const pages = (body as { links?: { pages?: { next?: string } } }).links?.pages?.next
        return pages || undefined
      })
      return rows.map((item) => ({ name: text(item, "name"), engine: text(item, "engine"), status: text(item, "status"), region: text(item, "region") }))
    },
  }
}

export function flyClient(token: string, fetchJSON: FetchJSON = defaultFetch) {
  return {
    async apps() {
      const body = await fetchJSON("https://api.fly.io/v1/apps", bearer(token))
      return array(body, "apps").map((item) => ({ Name: text(item, "name") || text(item, "Name"), Status: text(item, "status") || text(item, "Status") }))
    },
    async certificates(apps: string[]) {
      const certificates = []
      for (const app of apps) {
        const body = await fetchJSON(`https://api.fly.io/v1/apps/${app}/certificates`, bearer(token))
        const certs = (Array.isArray(body) ? body : array(body, "certificates")).map((item) => ({
          hostname: text(item, "hostname"),
          status: text(item, "client_status") || text(item, "clientStatus") || text(item, "status"),
        }))
        certificates.push({ app, certs })
      }
      return certificates
    },
  }
}

export function elasticClient(apiKey: string, fetchJSON: FetchJSON = defaultFetch) {
  return {
    async projects() {
      const projects = []
      for (const type of ["elasticsearch", "observability", "security"]) {
        try {
          const body = await fetchJSON(`https://api.elastic-cloud.com/api/v1/serverless/projects/${type}`, { authorization: `ApiKey ${apiKey}` })
          projects.push(...array(body, "items").map((item) => ({ name: text(item, "name") })))
        } catch (error) {
          if (error instanceof Error && error.message.endsWith("returned 404")) continue
          throw error
        }
      }
      return { projects }
    },
  }
}

export function resendClient(token: string, fetchJSON: FetchJSON = defaultFetch) {
  return {
    async inventory() {
      const domains = array(await fetchJSON("https://api.resend.com/domains", bearer(token)), "data")
      const apiKeys = array(await fetchJSON("https://api.resend.com/api-keys", bearer(token)), "data")
      return {
        domains: domains.map((item) => ({ name: text(item, "name") })),
        api_keys: apiKeys.map((item) => ({ name: text(item, "name") })),
      }
    },
    async send(message: { from: string; to: string; subject: string; idempotencyKey: string }) {
      const response = await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: { ...bearer(token), "content-type": "application/json", "idempotency-key": message.idempotencyKey },
        body: JSON.stringify({ from: message.from, to: message.to, subject: message.subject }),
      })
      if (!response.ok) throw new CheckError(`resend returned ${response.status}`, "blocked", { status: response.status })
    },
  }
}

type PostJSON = (url: string, headers: Record<string, string>, body: unknown) => Promise<unknown>

export function azureClient(token: string, fetchJSON: FetchJSON = defaultFetch, postJSON: PostJSON = defaultPost) {
  const arm = { authorization: `Bearer ${token}` }
  return {
    async offering() {
      const subscriptions = array(await fetchJSON("https://management.azure.com/subscriptions?api-version=2022-12-01", arm), "value")
      const keyVaults = []
      const storage = []
      for (const subscription of subscriptions) {
        const id = text(subscription, "subscriptionId")
        const vaults = array(await fetchJSON(`https://management.azure.com/subscriptions/${id}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01`, arm), "value")
        const accounts = array(await fetchJSON(`https://management.azure.com/subscriptions/${id}/providers/Microsoft.Storage/storageAccounts?api-version=2023-01-01`, arm), "value")
        keyVaults.push(...vaults.map((item) => ({ name: text(item, "name") })))
        storage.push(...accounts.map((item) => ({ name: text(item, "name") })))
      }
      return { key_vaults: keyVaults, storage_accounts: storage }
    },
    async keyVaultAudit() {
      const subscriptions = array(await fetchJSON("https://management.azure.com/subscriptions?api-version=2022-12-01", arm), "value")
      const vaults = []
      for (const subscription of subscriptions) {
        const listed = array(await fetchJSON(`https://management.azure.com/subscriptions/${text(subscription, "subscriptionId")}/providers/Microsoft.KeyVault/vaults?api-version=2022-07-01`, arm), "value")
        for (const vault of listed) {
          const id = text(vault, "id")
          const settings = array(await fetchJSON(`https://management.azure.com${id}/providers/Microsoft.Insights/diagnosticSettings?api-version=2021-05-01-preview`, arm), "value")
          vaults.push({
            name: text(vault, "name"),
            settings: settings.map((setting) => ({
              workspace: tail(text(setting, "workspaceId")),
              event_hub_namespace: namespaceFrom(text(setting, "eventHubAuthorizationRuleId")),
              logs: array(setting, "logs").map((log) => ({
                category: text(log, "category") || null,
                categoryGroup: text(log, "categoryGroup"),
                enabled: Boolean((log as { enabled?: boolean }).enabled),
              })),
            })),
          })
        }
      }
      return { vaults }
    },
    async inbox(input: { tenant: string; primary: string; marker: string; since: string; until: string }) {
      const listed = await fetchJSON(`https://graph.microsoft.com/v1.0/users?$select=mail&$filter=${encodeURIComponent(`mail eq '${input.primary.replaceAll("'", "''")}'`)}`, arm)
      const graphMails = rows(listed).map((item) => text(item, "mail")).filter((mail) => mail.length > 0)
      const mailbox = rows(await invoke(postJSON, token, input.tenant, "Get-Mailbox", { Identity: input.primary }))[0]
      const permissions = rows(await invoke(postJSON, token, input.tenant, "Get-MailboxPermission", { Identity: input.primary })).flatMap(permissionRows)
      const traces = rows(await invoke(postJSON, token, input.tenant, "Get-MessageTrace", { RecipientAddress: input.primary, StartDate: input.since, EndDate: input.until }))
      return {
        graph_mails: graphMails,
        primary: text(mailbox, "PrimarySmtpAddress"),
        recipient_type: text(mailbox, "RecipientTypeDetails"),
        addresses: strings(mailbox, "EmailAddresses"),
        permissions,
        traces: traces.map((trace) => ({
          received: text(trace, "Received"),
          sender_domain: text(trace, "SenderAddress").split("@").pop() ?? "",
          recipient: text(trace, "RecipientAddress"),
          status: text(trace, "Status"),
          subject_has_marker: text(trace, "Subject").includes(input.marker),
        })),
      }
    },
  }
}

async function invoke(postJSON: PostJSON, token: string, tenant: string, command: string, parameters: Record<string, string>) {
  return postJSON(`https://outlook.office365.com/adminapi/beta/${encodeURIComponent(tenant)}/InvokeCommand`, {
    authorization: `Bearer ${token}`,
    "x-anchormailbox": `APP:SystemMailbox{bb558c35-97f1-4cb9-8ff7-d53741dc928c}@${tenant}`,
    "content-type": "application/json",
  }, { CmdletInput: { CmdletName: command, Parameters: parameters } })
}

function permissionRows(item: unknown) {
  const listed = array(item, "PermissionList")
  const user = text(item, "User")
  if (listed.length > 0) {
    return listed.map((entry) => ({ user, rights: strings(entry, "AccessRights"), deny: Boolean((entry as { Deny?: boolean }).Deny) }))
  }
  return [{ user, rights: strings(item, "AccessRights"), deny: Boolean((item as { Deny?: boolean }).Deny) }]
}

export function tigrisClient(accessKey: string, secretKey: string, fetchText: (url: string, headers: Record<string, string>) => Promise<string> = defaultText) {
  return {
    async buckets() {
      const url = "https://t3.storage.dev/"
      const now = new Date()
      const headers = signS3({ method: "GET", url, accessKey, secretKey, now, region: "auto", service: "s3" })
      const xml = await fetchText(url, headers)
      return [...xml.matchAll(/<Name>([^<]+)<\/Name>/g)].map((match) => ({ name: match[1] }))
    },
  }
}

export function kubernetesClient(kubeconfig: string, request: (config: KubeConfig, path: string) => Promise<unknown> = kubeRequest) {
  const config = parseKubeconfig(kubeconfig)
  return { get: (path: string) => request(config, path) }
}

export function tlsClient() {
  return {
    async sample(hosts: string[]) {
      return { hosts: await Promise.all(hosts.map(sampleHost)) }
    },
  }
}

export function parseKubeconfig(text: string): KubeConfig {
  const trimmed = text.trim()
  if (trimmed.startsWith("{")) {
    const doc = JSON.parse(trimmed) as { server?: string; token?: string; ca?: string }
    if (!doc.server || !doc.token) throw new CheckError("kubeconfig is missing a server or token", "blocked")
    return { server: doc.server, token: doc.token, ca: doc.ca }
  }
  const server = /server:\s*(\S+)/.exec(trimmed)?.[1]
  const token = /token:\s*(\S+)/.exec(trimmed)?.[1]
  const ca = /certificate-authority-data:\s*(\S+)/.exec(trimmed)?.[1]
  if (!server || !token) throw new CheckError("kubeconfig is missing a server or token", "blocked")
  return { server, token, ca }
}

export function signS3(input: { method: string; url: string; accessKey: string; secretKey: string; now: Date; region: string; service: string }) {
  const parsed = new URL(input.url)
  const amzDate = input.now.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z")
  const day = amzDate.slice(0, 8)
  const payload = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  const canonical = [input.method, parsed.pathname || "/", parsed.searchParams.toString(), `host:${parsed.host}`, `x-amz-content-sha256:${payload}`, `x-amz-date:${amzDate}`, "", "host;x-amz-content-sha256;x-amz-date", payload].join("\n")
  const scope = `${day}/${input.region}/${input.service}/aws4_request`
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256(canonical)].join("\n")
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${input.secretKey}`, day), input.region), input.service), "aws4_request")
  const signature = createHmac("sha256", signingKey).update(stringToSign).digest("hex")
  return {
    authorization: `AWS4-HMAC-SHA256 Credential=${input.accessKey}/${scope}, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=${signature}`,
    "x-amz-date": amzDate,
    "x-amz-content-sha256": payload,
    host: parsed.host,
  }
}

type KubeConfig = { server: string; token: string; ca?: string }

function kubeRequest(config: KubeConfig, path: string) {
  const endpoint = new URL(path, config.server)
  return new Promise((resolve, reject) => {
    const request = https.request(endpoint, {
      headers: { authorization: `Bearer ${config.token}`, accept: "application/json" },
      ca: config.ca ? Buffer.from(config.ca, "base64") : undefined,
    }, (response) => {
      const chunks: Buffer[] = []
      response.on("data", (chunk) => chunks.push(chunk))
      response.on("end", () => {
        const text = Buffer.concat(chunks).toString("utf8")
        if ((response.statusCode ?? 500) >= 400) reject(new CheckError(`kubernetes returned ${response.statusCode}`, "blocked", { status: response.statusCode }))
        else resolve(JSON.parse(text) as unknown)
      })
    })
    request.on("error", reject)
    request.end()
  })
}

function sampleHost(host: string) {
  return new Promise<{ name: string; protocol: string; cipher: string; verification: string; issuer: string; not_after: string; http_status: number }>((resolve, reject) => {
    const socket = tls.connect({ host, port: 443, servername: host }, async () => {
      const certificate = socket.getPeerCertificate()
      const protocol = socket.getProtocol() ?? ""
      const cipher = socket.getCipher()
      const issuer = certificate.issuer?.O || certificate.issuer?.CN || ""
      const notAfter = certificate.valid_to ? new Date(certificate.valid_to).toISOString() : ""
      socket.end()
      const response = await fetch(`https://${host}`)
      resolve({ name: host, protocol, cipher: cipher?.name ?? "", verification: socket.authorized ? "OK" : "FAIL", issuer, not_after: notAfter, http_status: response.status })
    })
    socket.on("error", reject)
  })
}

async function cfList(url: string, token: string, fetchJSON: FetchJSON) {
  const rows = []
  let page = 1
  for (;;) {
    const body = await fetchJSON(`${url}${url.includes("?") ? "&" : "?"}page=${page}`, bearer(token)) as { success?: boolean; result?: unknown[]; result_info?: { total_pages?: number } }
    if (body.success === false) throw new CheckError("cloudflare request failed", "blocked")
    rows.push(...(body.result ?? []))
    if (page >= (body.result_info?.total_pages ?? 1)) return rows
    page += 1
  }
}

function rows(body: unknown) {
  if (Array.isArray(body)) return body
  const value = (body as { value?: unknown } | null)?.value
  if (Array.isArray(value)) return value
  if (body && typeof body === "object") return [body]
  return []
}

function strings(value: unknown, key: string) {
  const item = (value as Record<string, unknown> | undefined)?.[key]
  if (Array.isArray(item)) return item.filter((entry): entry is string => typeof entry === "string")
  return typeof item === "string" && item.length > 0 ? [item] : []
}

function array(body: unknown, key: string) {
  const value = (body as Record<string, unknown>)[key]
  return Array.isArray(value) ? value : []
}

function text(value: unknown, key: string) {
  if (!value || typeof value !== "object") return ""
  const item = (value as Record<string, unknown>)[key]
  return typeof item === "string" ? item : ""
}

function tail(value: string) {
  if (!value) return null
  const parts = value.split("/")
  return parts[parts.length - 1] || null
}

function namespaceFrom(value: string) {
  const match = /\/namespaces\/([^/]+)/.exec(value)
  return match?.[1]
}

function sha256(value: string) {
  return createHash("sha256").update(value).digest("hex")
}

function hmac(key: string | Buffer, value: string) {
  return createHmac("sha256", key).update(value).digest()
}

async function defaultPost(url: string, headers: Record<string, string>, body: unknown) {
  const response = await fetch(url, { method: "POST", headers: { accept: "application/json", ...headers }, body: JSON.stringify(body) })
  if (response.status === 401 || response.status === 403) throw new CheckError(`${new URL(url).host} returned ${response.status}`, "blocked", { status: response.status })
  if (!response.ok) throw new Error(`${new URL(url).host} returned ${response.status}`)
  return response.json() as Promise<unknown>
}

async function defaultText(url: string, headers: Record<string, string>) {
  const response = await fetch(url, { headers })
  if (!response.ok) throw new CheckError(`tigris returned ${response.status}`, "blocked", { status: response.status })
  return response.text()
}
