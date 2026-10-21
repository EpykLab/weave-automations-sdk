import { readFile } from "node:fs/promises"
import { memoryStore } from "../src/store.ts"
import { CheckError, type CheckContext, type Clients } from "../src/types.ts"

export async function readJSON<T>(name: string): Promise<T> {
  return JSON.parse(await readFile(new URL(`./fixtures/${name}`, import.meta.url), "utf8")) as T
}

export function context(options: { scope: unknown; payload?: unknown; now?: string; secret?: Record<string, string>; clients?: Partial<Clients> }): CheckContext {
  const now = new Date(options.now ?? "2026-10-21T18:00:00Z")
  return {
    recipeId: "fixture",
    binding: { scope: "evidence/scope/fixture.json" },
    now,
    secret(name) {
      return options.secret?.[name] ?? ""
    },
    store: memoryStore(now),
    http: { async get() { throw new Error("unused") } },
    clients: {
      github: () => { throw new Error("unused") },
      async payload() { return options.payload },
      ...options.clients,
    },
    async scope() {
      return { document: options.scope as never, digest: "digest" }
    },
    blocked: (message, detail) => new CheckError(message, "blocked", detail),
    failed: (message, detail) => new CheckError(message, "failed", detail),
    pending: (windowId) => new CheckError("pending", "pending", windowId),
  }
}
