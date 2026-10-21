import { defineCheck } from "./define.ts"
import { providerPayload } from "./read.ts"
import type { Check, CheckContext } from "./types.ts"

type Status = { name: string; status: string }

function check(id: string, secrets: string[], scopeKind: string, run: Check["run"]): Check {
  return defineCheck({ id, secrets, scopeKind, run })
}

function client<T>(value: T | undefined, name: string, ctx: CheckContext): T {
  if (!value) throw ctx.blocked(`${name} client is not configured`)
  return value
}

function names(items: Array<{ name?: string; Name?: string }> | undefined) {
  return (items ?? []).map((item) => item.name ?? item.Name ?? "")
}

export const auth0 = check("auth0.tenant-inventory", ["AUTH0_TOKEN"], "auth0_tenant_scope", async (ctx) => {
  const scope = await ctx.scope<{ tenant: string; organizations: Array<Status & { display_name: string }>; applications: Status[] }>(ctx.binding.scope)
  const live = await providerPayload(ctx, () => client(ctx.clients.auth0?.(ctx.secret("AUTH0_TOKEN")), "auth0", ctx).inventory(scope.document.tenant))
  const orgNames = new Set(scope.document.organizations.map((item) => item.name))
  const appNames = new Set(scope.document.applications.map((item) => item.name))
  const orgMatch = scope.document.organizations.filter((item) => item.status === "in_scope").every((item) =>
    live.organizations.filter((org) => org.name === item.name && org.display_name === item.display_name).length === 1)
  if (!orgMatch || live.organizations.some((item) => !orgNames.has(item.name)) || live.applications.some((item) => !appNames.has(item.name))) {
    throw ctx.blocked("Auth0 tenant inventory does not match the approved scope")
  }
  return {
    compliant: true,
    scope_digest: scope.digest,
    tenant: scope.document.tenant,
    organizations: scope.document.organizations.filter((item) => item.status === "in_scope").map((item) => ({ name: item.name, display_name: item.display_name })),
    applications: scope.document.applications.filter((item) => item.status === "in_scope").map((item) => item.name),
  }
})

export const cloudflare = check("cloudflare.dns-zone", ["CLOUDFLARE_API_TOKEN"], "cloudflare_zone_scope", async (ctx) => {
  const scope = await ctx.scope<{ zones: Status[]; required_records: Array<{ name: string; type: string }> }>(ctx.binding.scope)
  const live = await providerPayload(ctx, () => client(ctx.clients.cloudflare?.(ctx.secret("CLOUDFLARE_API_TOKEN")), "cloudflare", ctx).inventory())
  const classified = new Set(scope.document.zones.map((zone) => zone.name))
  if (live.zones.some((zone) => !classified.has(zone.name))) throw ctx.blocked("Cloudflare DNS inventory does not match the approved scope")
  const zone = scope.document.zones.find((item) => item.status === "in_scope")
  const required = scope.document.required_records.filter((record) => live.records.some((item) => item.name === record.name && item.type === record.type))
  if (!zone || required.length !== scope.document.required_records.length) throw ctx.failed("Cloudflare DNS inventory does not match the approved scope")
  return {
    compliant: true,
    scope_digest: scope.digest,
    zone: { name: zone.name },
    excluded_zone_count: scope.document.zones.filter((item) => item.status === "excluded").length,
    required_record_count: required.length,
    txt_record_count: live.records.filter((record) => record.type === "TXT").length,
  }
})

export const valkey = check("digitalocean.valkey-inventory", ["DIGITALOCEAN_TOKEN"], "do_database_scope", async (ctx) => {
  const scope = await ctx.scope<{ databases: Array<Status & { engine: string }> }>(ctx.binding.scope)
  const live = await providerPayload<Array<{ name: string; engine: string; status: string; region: string; connection?: { uri?: string } }>>(ctx, () => client(ctx.clients.digitalocean?.(ctx.secret("DIGITALOCEAN_TOKEN")), "digitalocean", ctx).databases())
  const classified = new Set(scope.document.databases.map((item) => item.name))
  const valkey = live.filter((item) => item.engine === "valkey")
  if (valkey.some((item) => !classified.has(item.name))) throw ctx.blocked("DigitalOcean database inventory does not match the approved scope")
  const wanted = new Set(scope.document.databases.filter((item) => item.status === "in_scope").map((item) => item.name))
  return {
    compliant: true,
    scope_digest: scope.digest,
    databases: valkey.filter((item) => wanted.has(item.name)).map((item) => ({ name: item.name, engine: item.engine, status: item.status, region: item.region })),
  }
})

export const flyApps = check("fly.apps", ["FLY_API_TOKEN"], "fly_app_scope", async (ctx) => {
  const scope = await ctx.scope<{ apps: Array<Status & { expected_status: string }> }>(ctx.binding.scope)
  const live = await providerPayload(ctx, () => client(ctx.clients.fly?.(ctx.secret("FLY_API_TOKEN")), "fly", ctx).apps())
  const wanted = scope.document.apps.filter((app) => app.status === "in_scope")
  if (wanted.some((app) => !live.some((item) => item.Name === app.name && item.Status === app.expected_status))) {
    throw ctx.failed("Fly app inventory does not match the approved scope")
  }
  return {
    compliant: true,
    scope_digest: scope.digest,
    apps: wanted.map((app) => ({ name: app.name, status: live.find((item) => item.Name === app.name)?.Status })),
  }
})

export const flyCerts = check("fly.certs", ["FLY_API_TOKEN"], "fly_app_scope", async (ctx) => {
  const scope = await ctx.scope<{ apps: Array<{ name: string; hostname: string; status: string }> }>(ctx.binding.scope)
  const wanted = scope.document.apps.filter((app) => app.status === "in_scope")
  const live = await providerPayload(ctx, () => client(ctx.clients.fly?.(ctx.secret("FLY_API_TOKEN")), "fly", ctx).certificates(wanted.map((app) => app.name)))
  const certificates = wanted.map((app) => {
    const cert = live.find((item) => item.app === app.name)?.certs.find((item) => item.hostname === app.hostname)
    if (!cert || cert.status !== "Ready") throw ctx.failed("Fly certificate inventory does not match the approved scope")
    return { hostname: cert.hostname, status: cert.status }
  })
  return { compliant: true, scope_digest: scope.digest, certificates }
})

export const tigris = check("tigris.buckets", ["TIGRIS_ACCESS_KEY", "TIGRIS_SECRET_ACCESS_KEY"], "tigris_bucket_scope", async (ctx) => {
  const scope = await ctx.scope<{ organization: string; buckets: Status[] }>(ctx.binding.scope)
  const live = await providerPayload(ctx, () => client(ctx.clients.tigris?.(ctx.secret("TIGRIS_ACCESS_KEY"), ctx.secret("TIGRIS_SECRET_ACCESS_KEY")), "tigris", ctx).buckets())
  const classified = new Set(scope.document.buckets.map((item) => item.name))
  if (names(live).some((name) => !classified.has(name))) throw ctx.blocked("Tigris bucket inventory does not match the approved scope")
  return {
    compliant: true,
    scope_digest: scope.digest,
    organization: scope.document.organization,
    in_scope_count: scope.document.buckets.filter((item) => item.status === "in_scope").length,
    excluded_count: scope.document.buckets.filter((item) => item.status === "excluded").length,
    buckets: scope.document.buckets.filter((item) => item.status === "in_scope").map((item) => item.name),
  }
})

export const elastic = check("elastic.projects", ["ELASTIC_API_KEY"], "elastic_project_scope", async (ctx) => {
  const scope = await ctx.scope<{ projects: Array<Status & { type: string; region_id: string; alias: string; tier: string }> }>(ctx.binding.scope)
  const live = await providerPayload(ctx, () => client(ctx.clients.elastic?.(ctx.secret("ELASTIC_API_KEY")), "elastic", ctx).projects())
  const classified = new Set(scope.document.projects.map((item) => item.name))
  if (live.projects.some((item) => !classified.has(item.name))) throw ctx.blocked("Elastic Cloud project inventory does not match the approved scope")
  return {
    compliant: true,
    scope_digest: scope.digest,
    projects: scope.document.projects.filter((item) => item.status === "in_scope").map((item) => ({ name: item.name, type: item.type, region_id: item.region_id, alias: item.alias, tier: item.tier })),
  }
})

export const tls = check("tls.handshake", [], "tenant_tls_sample", async (ctx) => {
  const scope = await ctx.scope<{ hosts?: Array<{ name: string; status: string }> }>(ctx.binding.scope)
  const live = await providerPayload<{ hosts: Array<{ name?: string; protocol: string; cipher: string; verification: string; issuer: string; not_after: string; http_status: number; certificate?: string; private_key?: string }> }>(ctx, () => {
    const hosts = (scope.document.hosts ?? []).filter((host) => host.status === "in_scope").map((host) => host.name)
    return client(ctx.clients.tls?.(), "tls", ctx).sample(hosts)
  })
  if (live.hosts.some((host) => host.protocol !== "TLSv1.3" || host.verification !== "OK" || host.http_status !== 200)) {
    throw ctx.failed("tenant TLS sample does not match the approved scope")
  }
  const dates = live.hosts.map((host) => host.not_after).sort()
  return {
    compliant: true,
    scope_digest: scope.digest,
    sample_count: live.hosts.length,
    protocols: [...new Set(live.hosts.map((host) => host.protocol))],
    ciphers: [...new Set(live.hosts.map((host) => host.cipher))],
    verifications: [...new Set(live.hosts.map((host) => host.verification))],
    issuers: [...new Set(live.hosts.map((host) => host.issuer))],
    http_statuses: [...new Set(live.hosts.map((host) => host.http_status))],
    earliest_not_after: dates[0],
    latest_not_after: dates[dates.length - 1],
  }
})
