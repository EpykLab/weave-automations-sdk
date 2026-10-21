export interface Check {
  id: string
  secrets: string[]
  scopeKind: string
  run(ctx: CheckContext): Promise<unknown>
}

export interface Action {
  id: string
  secrets: string[]
  scopeKind: string
  run(ctx: CheckContext): Promise<ActionReceipt>
}

export interface ActionReceipt {
  window_id: string
  retry?: { budget_ms: number; initial_ms?: number; max_interval_ms?: number }
}

export interface Scoped<T> {
  document: T
  digest: string
}

export interface ActionRow {
  recipeId: string
  action: string
  windowId: string
  status: "accepted" | "observed"
  deadline: string
}

export interface ActionStore {
  window(recipeId: string, action: string, everyMs: number): string
  put(row: ActionRow): Promise<ActionRow>
  current(recipeId: string, action: string): Promise<ActionRow | null>
  markObserved(recipeId: string, action: string): Promise<void>
}

export interface CheckContext {
  recipeId: string
  binding: { scope: string }
  now: Date
  secret(name: string): string
  scope<T>(path: string): Promise<Scoped<T>>
  store: ActionStore
  http: { get(url: string): Promise<{ ok: boolean; status: number; json(): Promise<unknown> }> }
  clients: Clients
  blocked(message: string, detail?: unknown): Error
  failed(message: string, detail?: unknown): Error
  pending(windowId: string): Error
}

export interface Clients {
  github(token: string): GitHubClient
  payload?(name: string): Promise<unknown>
  resend?(token: string): {
    inventory(): Promise<{ domains: Array<{ name: string }>; api_keys: Array<{ name: string }> }>
    send(message: { from: string; to: string; subject: string; idempotencyKey: string }): Promise<void>
  }
  auth0?(token: string): { inventory(tenant: string): Promise<{ organizations: Array<{ name: string; display_name: string }>; applications: Array<{ name: string }> }> }
  cloudflare?(token: string): { inventory(): Promise<{ zones: Array<{ name: string }>; records: Array<{ name: string; type: string }> }> }
  digitalocean?(token: string): { databases(): Promise<Array<{ name: string; engine: string; status: string; region: string }>> }
  fly?(token: string): { apps(): Promise<Array<{ Name: string; Status: string }>>; certificates(apps: string[]): Promise<Array<{ app: string; certs: Array<{ hostname: string; status: string }> }>> }
  tigris?(accessKey: string, secretKey: string): { buckets(): Promise<Array<{ name: string }>> }
  elastic?(apiKey: string): { projects(): Promise<{ projects: Array<{ name: string }> }> }
  azure?(token: string): {
    offering(): Promise<{ key_vaults: Array<{ name: string }>; storage_accounts: Array<{ name: string }> }>
    keyVaultAudit(): Promise<{ vaults: Array<{ name: string; settings: Array<{ workspace?: string | null; event_hub_namespace?: string; logs?: Array<{ category?: string | null; categoryGroup?: string; enabled?: boolean }> }> }> }>
    inbox(input: { tenant: string; primary: string; marker: string; since: string; until: string }): Promise<{
      graph_mails?: string[]
      primary?: string
      recipient_type?: string
      addresses?: string[]
      permissions?: Array<{ user: string; rights: string[]; deny: boolean }>
      traces?: Array<{ received?: string; sender_domain?: string; recipient?: string; status?: string; subject_has_marker?: boolean }>
    }>
  }
  kubernetes?(kubeconfig: string): { get(path: string): Promise<unknown> }
  tls?(): { sample(hosts: string[]): Promise<{ hosts: Array<{ name: string; protocol: string; cipher: string; verification: string; issuer: string; not_after: string; http_status: number }> }> }
}

export interface GitHubClient {
  get<T>(path: string, options?: { allowMissing?: boolean }): Promise<T | null>
  paginate<T>(path: string): Promise<T[]>
}

export interface RecipeBinding {
  id: string
  check: Check
  scope: string
  schedule: "daily" | "weekly"
  action?: {
    use: Action
    schedule: "daily" | "weekly"
    retry: { budgetMs: number; initialMs?: number; maxIntervalMs?: number }
  }
}

export interface Caller {
  subject: string
  issuer?: string
  allows(recipeId: string, operation: "run" | "act"): boolean
}

export interface HttpRequest {
  method: string
  path: string
  token?: string
  body?: unknown
}

export interface HttpResponse {
  status: number
  body: unknown
}

export class CheckError extends Error {
  kind: "blocked" | "failed" | "pending"
  detail?: unknown
  constructor(message: string, kind: "blocked" | "failed" | "pending", detail?: unknown) {
    super(message)
    this.kind = kind
    this.detail = detail
  }
}
