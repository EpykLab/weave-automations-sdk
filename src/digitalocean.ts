import path from "node:path"
import { readFile } from "node:fs/promises"
import { accessCaller, type AccessSubject } from "./auth.ts"
import { actionsClaims } from "./oidc.ts"
import { defaultClients } from "./providers.ts"
import { connectPostgres, postgresStore } from "./postgres.ts"
import { createRouter, type App } from "./router.ts"
import { CheckError, type ActionStore, type RecipeBinding } from "./types.ts"

export interface PlatformArgs {
  __ow_method?: string
  __ow_path?: string
  __ow_headers?: Record<string, string>
  [key: string]: unknown
}

type PlatformInput = { group: string; recipes: RecipeBinding[] } & Partial<Omit<App, "recipes">>

let pool: ReturnType<typeof connectPostgres> | undefined

export function serve(input: PlatformInput) {
  return async function main(args: PlatformArgs) {
    try {
      const now = (input.now ?? (() => new Date()))()
      const handle = createRouter({
        recipes: input.recipes,
        authenticate: input.authenticate ?? authenticate(await loadSubjects()),
        store: input.store ?? lazyStore(now),
        now: () => now,
        readScope: input.readScope ?? readScope,
        secret: input.secret ?? secret,
        clients: input.clients ?? defaultClients(),
      })
      const headers = args.__ow_headers ?? {}
      const authorization = headers.authorization ?? headers.Authorization ?? ""
      const token = authorization.startsWith("Bearer ") ? authorization.slice("Bearer ".length) : undefined
      const response = await handle({
        method: String(args.__ow_method ?? "GET").toUpperCase(),
        path: String(args.__ow_path ?? "/"),
        token,
      })
      return { statusCode: response.status, body: response.body }
    } catch (error) {
      const message = error instanceof Error ? error.message : "check failed"
      return { statusCode: 500, body: { error: "failed", message } }
    }
  }
}

function authenticate(loaded: AccessSubject[]) {
  return async (token: string) => {
    if (token && token === process.env.OPERATOR_TOKEN) {
      return accessCaller(loaded, { issuer: "weave", subject: "operators" })
    }
    if (token && token === process.env.COLLECTOR_TOKEN) {
      return accessCaller(loaded, { issuer: "https://stellarbridge.app/weave/automations", subject: "collector" })
    }
    const claims = await actionsClaims(token, new Date(), loadJwks)
    if (!claims) return undefined
    return accessCaller(loaded, claims)
  }
}

async function loadJwks(url: string) {
  const response = await fetch(url)
  if (!response.ok) return { keys: [] }
  return await response.json() as { keys: [] }
}

function lazyStore(now: Date): ActionStore {
  let inner: ActionStore | undefined
  const open = async () => {
    if (inner) return inner
    const url = process.env.DATABASE_URL
    if (!url) throw new CheckError("DATABASE_URL is not configured", "blocked")
    if (!pool) pool = connectPostgres(url)
    inner = postgresStore(pool, now)
    return inner
  }
  return {
    window(recipeId, action, everyMs) {
      const start = Math.floor(now.getTime() / everyMs) * everyMs
      return new Date(start).toISOString().replace(".000Z", "Z")
    },
    async put(row) {
      return (await open()).put(row)
    },
    async current(recipeId, action) {
      return (await open()).current(recipeId, action)
    },
    async markObserved(recipeId, action) {
      return (await open()).markObserved(recipeId, action)
    },
  }
}

async function loadSubjects() {
  const text = await readFile(path.join(process.cwd(), "access.json"), "utf8")
  return (JSON.parse(text) as { subjects: AccessSubject[] }).subjects
}

async function readScope(scopePath: string) {
  const name = path.basename(scopePath)
  if (!name || name !== scopePath.split("/").pop()) throw new CheckError("scope path escapes the function", "blocked")
  const text = await readFile(path.join(process.cwd(), "scopes", name), "utf8")
  return JSON.parse(text) as unknown
}

function secret(name: string) {
  const value = process.env[name]
  if (!value) throw new CheckError(`secret ${name} is not configured`, "blocked")
  return value
}
