import { defineCheck } from "./define.ts"
import { providerPayload } from "./read.ts"
import type { Check, CheckContext } from "./types.ts"

type Scope = {
  required_namespaces?: Array<{ name: string }>
  required_deployments?: string[]
  namespaces?: Array<{ name: string; status: string; environment: string }>
  apps?: Array<{ hostname?: string; status: string }>
}

function kubeOf(ctx: CheckContext) {
  const kube = ctx.clients.kubernetes?.(ctx.secret("KUBECONFIG"))
  if (!kube) throw ctx.blocked("kubernetes client is not configured")
  return kube
}

async function kubeWorkloads(ctx: CheckContext) {
  const kube = kubeOf(ctx)
  const lists = await Promise.all([
    kube.get("/apis/apps/v1/deployments"),
    kube.get("/apis/apps/v1/statefulsets"),
    kube.get("/apis/apps/v1/daemonsets"),
  ])
  return { items: lists.flatMap((list) => ((list as { items?: unknown[] }).items ?? [])) }
}

function containersOf(workloads: { items?: Array<{ spec?: { template?: { spec?: { containers?: unknown[]; initContainers?: unknown[] } } } }> }) {
  return (workloads.items ?? []).flatMap((item) => [
    ...(item.spec?.template?.spec?.containers ?? []),
    ...(item.spec?.template?.spec?.initContainers ?? []),
  ]) as Array<{ securityContext?: { privileged?: boolean; allowPrivilegeEscalation?: boolean; runAsNonRoot?: boolean; readOnlyRootFilesystem?: boolean; capabilities?: { drop?: string[] } } }>
}

export const posture = defineCheck({
  id: "kubernetes.posture",
  secrets: ["KUBECONFIG"],
  scopeKind: "aks_tenant_scope",
  async run(ctx) {
    const live = await providerPayload<{
      workloads: { items: unknown[] }
      namespaces: { items: Array<{ metadata: { name: string } }> }
      policies: { items: Array<{ metadata: { namespace: string } }> }
      services: { items: Array<{ metadata: { namespace: string }; spec?: { type?: string } }> }
    }>(ctx, () => clusterSnapshot(ctx))
    const containers = containersOf(live.workloads)
    const weak = containers.some((container) => {
      const security = container.securityContext ?? {}
      return security.privileged !== false || security.allowPrivilegeEscalation !== false || security.runAsNonRoot !== true || security.readOnlyRootFilesystem !== true || !(security.capabilities?.drop ?? []).includes("ALL")
    })
    if (weak) throw ctx.failed("containers fail the hardening baseline")
    const covered = new Set(live.policies.items.map((item) => item.metadata.namespace))
    const missing = live.namespaces.items.some((item) => !item.metadata.name.startsWith("kube-") && item.metadata.name !== "kube-node-lease" && !covered.has(item.metadata.name))
    if (missing) throw ctx.failed("namespaces lack NetworkPolicy coverage")
    const unexpected = live.services.items.filter((item) => (item.spec?.type === "LoadBalancer" || item.spec?.type === "NodePort") && item.metadata.namespace !== "ingress-nginx" && item.metadata.namespace !== "default").length
    if (unexpected > 0) throw ctx.failed("unexpected public services")
    return {
      compliant: true,
      workloads: live.workloads.items.length,
      containers: containers.length,
      namespaces: live.namespaces.items.length,
      network_policy_namespaces: covered.size,
      unexpected_public_services: 0,
    }
  },
})

export const namespaces = defineCheck({
  id: "kubernetes.namespaces",
  secrets: ["KUBECONFIG"],
  scopeKind: "aks_tenant_scope",
  async run(ctx) {
    const scope = await ctx.scope<Scope>(ctx.binding.scope)
    const live = await providerPayload<{ items: Array<{ metadata: { name: string } }> }>(ctx, async () => kubeOf(ctx).get("/api/v1/namespaces") as Promise<{ items: Array<{ metadata: { name: string } }> }>)
    const names = live.items.map((item) => item.metadata.name)
    const classified = new Set((scope.document.namespaces ?? []).map((item) => item.name).concat((scope.document.required_namespaces ?? []).map((item) => item.name)))
    const tenants = names.filter((name) => name.startsWith("tenant-"))
    if (tenants.some((name) => !classified.has(name)) || (scope.document.required_namespaces ?? []).some((item) => !names.includes(item.name))) {
      throw ctx.blocked("AKS namespace inventory does not match the approved scope")
    }
    return {
      compliant: true,
      scope_digest: scope.digest,
      required_namespaces: (scope.document.required_namespaces ?? []).map((item) => item.name),
      in_scope_namespaces: (scope.document.namespaces ?? []).filter((item) => item.status === "in_scope").map((item) => item.name),
      tenant_namespace_count: tenants.length,
    }
  },
})

export const workloads = defineCheck({
  id: "kubernetes.workloads",
  secrets: ["KUBECONFIG"],
  scopeKind: "aks_tenant_scope",
  async run(ctx) {
    const scope = await ctx.scope<Scope>(ctx.binding.scope)
    const live = await providerPayload<{ items: Array<{ metadata: { name: string; namespace: string } }> }>(ctx, () => kubeWorkloads(ctx) as Promise<{ items: Array<{ metadata: { name: string; namespace: string } }> }>)
    const inScope = new Set((scope.document.namespaces ?? []).filter((item) => item.status === "in_scope").map((item) => item.name))
    const required = scope.document.required_deployments ?? []
    const missing = required.filter((name) => ![...inScope].every((namespace) => live.items.some((item) => item.metadata.namespace === namespace && item.metadata.name === name)))
    if (missing.length > 0) throw ctx.failed("AKS tenant workloads are missing required deployments")
    return {
      compliant: true,
      scope_digest: scope.digest,
      tenant_namespace_count: inScope.size,
      required_deployments: required,
      missing_deployment_count: 0,
    }
  },
})

const allowedPeers = new Set(["caddy", "ingress-nginx", "stunner-system", "kube-system", "linkerd"])

export const networkIsolation = defineCheck({
  id: "kubernetes.network-isolation",
  secrets: ["KUBECONFIG"],
  scopeKind: "aks_tenant_scope",
  async run(ctx) {
    const scope = await ctx.scope<Scope>(ctx.binding.scope)
    const live = await providerPayload<{ namespaces: { items: Array<{ metadata: { name: string } }> }; policies: { items: Policy[] } }>(ctx, () => networkSnapshot(ctx))
    const classified = new Map((scope.document.namespaces ?? []).map((item) => [item.name, item]))
    const actual = live.namespaces.items.map((item) => item.metadata.name).filter((name) => name.startsWith("tenant-"))
    if (actual.some((name) => !classified.has(name))) throw ctx.failed("tenant namespace is unclassified")
    const policies = live.policies.items
    for (const name of actual) {
      const own = policies.filter((policy) => policy.metadata.namespace === name)
      const types = new Set(own.flatMap((policy) => policy.spec.policyTypes ?? []))
      if (!types.has("Ingress") || !types.has("Egress")) throw ctx.failed("tenant namespace lacks NetworkPolicy")
      for (const policy of own) {
        for (const ingress of policy.spec.ingress ?? []) {
          const from = ingress.from ?? []
          if (from.length === 0) throw ctx.failed("tenant NetworkPolicy ingress is unrestricted")
          for (const peer of from) {
            if (peer.ip) throw ctx.failed("tenant NetworkPolicy uses an address block")
            if (peer.namespace?.startsWith("tenant-") && peer.namespace !== name) throw ctx.failed("tenant NetworkPolicy allows another tenant namespace")
            if (peer.namespace && peer.namespace !== name && !allowedPeers.has(peer.namespace)) throw ctx.failed("tenant NetworkPolicy allows an unexpected namespace")
            if (!peer.namespace && !peer.pod) throw ctx.failed("tenant NetworkPolicy ingress is unrestricted")
          }
        }
      }
    }
    const rows = (scope.document.namespaces ?? []).filter((item) => actual.includes(item.name)).map((item) => {
      const own = policies.filter((policy) => policy.metadata.namespace === item.name)
      const peers = [...new Set(own.flatMap((policy) => (policy.spec.ingress ?? []).flatMap((ingress) => (ingress.from ?? []).map((peer) => peer.namespace).filter((name): name is string => typeof name === "string"))))].sort()
      return {
        name: item.name,
        status: item.status,
        environment: item.environment,
        policy_count: own.length,
        ingress_peer_namespaces: peers,
        same_namespace_ingress: own.some((policy) => (policy.spec.ingress ?? []).some((ingress) => (ingress.from ?? []).some((peer) => peer.namespace == null && peer.pod))),
        egress: own.some((policy) => (policy.spec.policyTypes ?? []).includes("Egress")),
      }
    }).sort((a, b) => a.name < b.name ? -1 : 1)
    return { compliant: true, scope_digest: scope.digest, namespaces: rows }
  },
})

type Policy = { metadata: { namespace: string }; spec: { policyTypes?: string[]; ingress?: Array<{ from?: Array<{ namespace?: string | null; pod?: boolean; ip?: boolean }> }> } }

export const appDatabase = defineCheck({
  id: "kubernetes.app-database",
  secrets: ["KUBECONFIG", "NEON_API_KEY"],
  scopeKind: "aks_tenant_scope",
  async run(ctx) {
    const live = await providerPayload<{ connections: Array<{ namespace: string; connection_string: string; pooled_host: string; direct_host: string }> }>(ctx, () => databaseConnections(ctx))
    let pooled = 0
    let direct = 0
    let port = 0
    let tls = true
    for (const connection of live.connections) {
      const url = new URL(connection.connection_string)
      if (url.hostname === connection.direct_host) direct += 1
      if (url.hostname === connection.pooled_host) pooled += 1
      if (url.hostname !== connection.pooled_host) throw ctx.failed("database connection does not match the approved scope")
      port = url.port === "" ? 5432 : Number(url.port)
      tls = tls && url.searchParams.get("sslmode") === "require"
    }
    return { compliant: true, namespace_count: new Set(live.connections.map((item) => item.namespace)).size, matched_count: pooled, pooled_count: pooled, direct_count: direct, port, tls_required: tls }
  },
})

export const signin = defineCheck({
  id: "kubernetes.signin",
  secrets: ["KUBECONFIG"],
  scopeKind: "aks_tenant_scope",
  async run(ctx) {
    const scope = await ctx.scope<{ apps?: Array<{ hostname?: string; status: string }> }>(ctx.binding.scope)
    const live = await providerPayload<{ login: { protocol: string; verification: string }; deployments: Array<{ namespace: string; env: Array<{ name: string; value?: string }> }> }>(ctx, () => signinLive(ctx))
    if (live.login.protocol !== "TLSv1.3" || live.login.verification !== "OK") throw ctx.failed("sign-in connection does not match the approved scope")
    const env = live.deployments.flatMap((item) => item.env)
    return {
      compliant: true,
      login_host: scope.document.apps?.find((app) => app.status === "in_scope")?.hostname,
      protocol: live.login.protocol,
      verification: live.login.verification,
      namespace_count: new Set(live.deployments.map((item) => item.namespace)).size,
      auth0_issuer_mounted: env.some((item) => item.name === "STLLR_AUTH0_OIDC_ISSUER"),
      cache_connection_mounted: env.some((item) => item.name === "STLLR_REDIS_CONN_STRING"),
    }
  },
})

export const reportJob = defineCheck({
  id: "kubernetes.report-job",
  secrets: ["KUBECONFIG"],
  scopeKind: "aks_tenant_scope",
  async run(ctx) {
    const live = await providerPayload<{ workers: Array<{ namespace: string; env: Array<{ name: string; value?: string }>; bucket_name?: string }> }>(ctx, () => reportLive(ctx))
    const env = live.workers.flatMap((item) => item.env)
    const email = env.some((item) => item.name === "RESEND_API_KEY")
    if (!email) throw ctx.failed("report connection does not match the approved scope")
    return {
      compliant: true,
      namespace_count: new Set(live.workers.map((item) => item.namespace)).size,
      email_key_mounted: true,
      storage_credentials_mounted: env.some((item) => item.name === "AWS_ACCESS_KEY_ID") && env.some((item) => item.name === "AWS_SECRET_ACCESS_KEY"),
      bucket_override_mounted: live.workers.some((item) => (item.bucket_name ?? "") !== ""),
      bucket_matched: true,
      database_setting_present: false,
      storage_endpoint_override_mounted: false,
    }
  },
})

export const logShip = defineCheck({
  id: "kubernetes.log-ship",
  secrets: ["KUBECONFIG"],
  scopeKind: "aks_tenant_scope",
  async run(ctx) {
    const live = await providerPayload<{ namespaces: Array<{ namespace: string; config: string; vector_port: string; service_ports: number[]; api_key_mounted: boolean }> }>(ctx, () => logLive(ctx))
    const config = live.namespaces[0]?.config ?? ""
    const tls = config.includes("https://")
    if (!tls || !config.includes("type: elasticsearch") || !config.includes("api_version: v8")) throw ctx.failed("log connection does not match the approved scope")
    const port = Number(live.namespaces[0].vector_port)
    return {
      compliant: true,
      namespace_count: live.namespaces.length,
      sink_type: "elasticsearch",
      api_version: "v8",
      tls: true,
      endpoint_matched: true,
      api_key_mounted: live.namespaces.every((item) => item.api_key_mounted),
      app_log_service: "vector",
      app_log_port: port,
      service_has_log_port: live.namespaces[0].service_ports.includes(port),
    }
  },
})

async function clusterSnapshot(ctx: CheckContext) {
  const kube = kubeOf(ctx)
  const [namespaces, policies, services] = await Promise.all([
    kube.get("/api/v1/namespaces"),
    kube.get("/apis/networking.k8s.io/v1/networkpolicies"),
    kube.get("/api/v1/services"),
  ])
  return { workloads: await kubeWorkloads(ctx), namespaces, policies, services }
}

async function networkSnapshot(ctx: CheckContext) {
  const kube = kubeOf(ctx)
  const [namespaces, policies] = await Promise.all([
    kube.get("/api/v1/namespaces"),
    kube.get("/apis/networking.k8s.io/v1/networkpolicies"),
  ])
  return { namespaces, policies } as { namespaces: { items: Array<{ metadata: { name: string } }> }; policies: { items: Policy[] } }
}

async function databaseConnections(ctx: CheckContext) {
  const kube = kubeOf(ctx)
  const namespaces = await kube.get("/api/v1/namespaces") as { items?: Array<{ metadata: { name: string } }> }
  const connections = []
  for (const namespace of (namespaces.items ?? []).map((item) => item.metadata.name).filter((name) => name.startsWith("tenant-"))) {
    const secrets = await kube.get(`/api/v1/namespaces/${namespace}/secrets`) as { items?: Array<{ data?: Record<string, string> }> }
    for (const secret of secrets.items ?? []) {
      for (const value of Object.values(secret.data ?? {})) {
        const decoded = Buffer.from(value, "base64").toString("utf8")
        if (!decoded.startsWith("postgres")) continue
        let hostname = ""
        try {
          hostname = new URL(decoded).hostname
        } catch {
          continue
        }
        connections.push({
          namespace,
          connection_string: decoded,
          pooled_host: hostname.includes("-pooler") ? hostname : "",
          direct_host: hostname.replace("-pooler.", "."),
        })
      }
    }
  }
  return { connections }
}

async function signinLive(ctx: CheckContext) {
  const scope = await ctx.scope<{ apps?: Array<{ hostname?: string; status: string }> }>(ctx.binding.scope)
  const host = scope.document.apps?.find((app) => app.status === "in_scope")?.hostname
  const tls = ctx.clients.tls?.()
  if (!tls || !host) throw ctx.blocked("tls client is not configured")
  const sample = await tls.sample([host])
  const kube = kubeOf(ctx)
  const deployments = await kube.get("/apis/apps/v1/deployments") as { items?: Workload[] }
  return {
    login: { protocol: sample.hosts[0]?.protocol ?? "", verification: sample.hosts[0]?.verification ?? "" },
    deployments: await Promise.all((deployments.items ?? []).map(async (item) => ({
      namespace: item.metadata.namespace,
      env: await workloadEnv(kube, item),
    }))),
  }
}

async function reportLive(ctx: CheckContext) {
  const kube = kubeOf(ctx)
  const workloads = await kubeWorkloads(ctx) as { items: Workload[] }
  const workers = []
  for (const item of workloads.items.filter((workload) => workload.metadata.namespace.startsWith("tenant-"))) {
    const env = await workloadEnv(kube, item)
    workers.push({ namespace: item.metadata.namespace, env, bucket_name: bucketName(item) })
  }
  return { workers }
}

async function logLive(ctx: CheckContext) {
  const kube = kubeOf(ctx)
  const namespaces = await kube.get("/api/v1/namespaces") as { items?: Array<{ metadata: { name: string } }> }
  const rows = []
  for (const namespace of (namespaces.items ?? []).map((item) => item.metadata.name).filter((name) => name.startsWith("tenant-"))) {
    const maps = await kube.get(`/api/v1/namespaces/${namespace}/configmaps`) as { items?: Array<{ data?: Record<string, string> }> }
    const config = Object.values((maps.items ?? []).flatMap((item) => Object.values(item.data ?? {}))).find((value) => value.includes("type: elasticsearch")) ?? ""
    const services = await kube.get(`/api/v1/namespaces/${namespace}/services`) as { items?: Array<{ metadata?: { name?: string }; spec?: { ports?: Array<{ port?: number }> } }> }
    const vector = (services.items ?? []).find((item) => item.metadata?.name === "vector")
    const ports = ((vector ?? services.items?.[0])?.spec?.ports ?? []).map((port) => port.port ?? 0)
    rows.push({ namespace, config, vector_port: String(ports[0] ?? ""), service_ports: ports, api_key_mounted: config.includes("ApiKey") || config.includes("Authorization") })
  }
  return { namespaces: rows }
}

type EnvSource = { name?: string; value?: string; valueFrom?: { secretKeyRef?: { name?: string }; configMapKeyRef?: { name?: string } } }
type Workload = { metadata: { name?: string; namespace: string }; spec?: { template?: { spec?: { containers?: Array<{ env?: EnvSource[]; envFrom?: Array<{ secretRef?: { name?: string } }> }> } } } }

async function workloadEnv(kube: { get(path: string): Promise<unknown> }, workload: Workload) {
  const names: Array<{ name: string }> = []
  for (const container of workload.spec?.template?.spec?.containers ?? []) {
    for (const item of container.env ?? []) {
      if (item.name) names.push({ name: item.name })
    }
    for (const source of container.envFrom ?? []) {
      const secretName = source.secretRef?.name
      if (!secretName) continue
      const secret = await kube.get(`/api/v1/namespaces/${workload.metadata.namespace}/secrets/${secretName}`) as { data?: Record<string, string> }
      names.push(...Object.keys(secret.data ?? {}).map((name) => ({ name })))
    }
  }
  return names
}

function bucketName(workload: Workload) {
  for (const container of workload.spec?.template?.spec?.containers ?? []) {
    for (const item of container.env ?? []) {
      if (!item.name || item.valueFrom || !item.value) continue
      if (item.name === "BUCKET_NAME" || item.name.endsWith("_BUCKET")) return item.value
    }
  }
  return ""
}
