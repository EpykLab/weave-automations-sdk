import { scopeDigest } from "./digest.ts"
import { CheckError, type ActionStore, type CheckContext, type HttpRequest, type HttpResponse, type RecipeBinding } from "./types.ts"

export interface App {
  recipes: RecipeBinding[]
  authenticate(token: string): { subject: string; allows(recipeId: string, operation: "run" | "act"): boolean } | undefined | Promise<{ subject: string; allows(recipeId: string, operation: "run" | "act"): boolean } | undefined>
  store: ActionStore
  now(): Date
  readScope(path: string): Promise<unknown>
  secret(name: string): string
  clients: CheckContext["clients"]
}

export function createRouter(app: App) {
  return async function handle(req: HttpRequest): Promise<HttpResponse> {
    const caller = req.token ? await app.authenticate(req.token) : undefined
    if (!caller) return { status: 401, body: { error: "unauthorized" } }

    if (req.method === "GET" && req.path === "/recipes") {
      return {
        status: 200,
        body: { recipes: app.recipes.filter((recipe) => caller.allows(recipe.id, "run")).map((recipe) => recipe.id) },
      }
    }

    const action = req.path.match(/^\/recipes\/([^/]+)\/actions\/([^/]+)$/)
    if (req.method === "POST" && action) {
      const recipe = find(app, action[1])
      if (!recipe?.action || recipe.action.use.id !== action[2]) return { status: 404, body: { error: "unknown_action" } }
      if (!caller.allows(recipe.id, "act")) return { status: 403, body: { error: "forbidden" } }
      const receipt = await recipe.action.use.run(context(app, recipe, caller))
      return { status: 202, body: { recipe_id: recipe.id, action: action[2], ...receipt } }
    }

    const run = req.path.match(/^\/recipes\/([^/]+)\/runs$/)
    if (req.method === "POST" && run) {
      const recipe = find(app, run[1])
      if (!recipe) return { status: 404, body: { error: "unknown_recipe" } }
      if (!caller.allows(recipe.id, "run")) return { status: 403, body: { error: "forbidden" } }
      try {
        const observation = await recipe.check.run(context(app, recipe, caller))
        return {
          status: 200,
          body: {
            schema_version: 1,
            run: {
              recipe_id: recipe.id,
              status: "complete",
              artifacts: [
                { path: "artifacts/result.json", role: "capture", media_type: "application/json", body: observation },
              ],
            },
          },
        }
      } catch (error) {
        if (error instanceof CheckError && error.kind === "pending") {
          return { status: 202, body: { status: "pending", window_id: error.detail } }
        }
        if (error instanceof CheckError) return { status: 422, body: { error: error.kind, message: error.message, detail: error.detail } }
        throw error
      }
    }

    return { status: 404, body: { error: "not_found", method: req.method, path: req.path } }
  }
}

function find(app: App, id: string) {
  return app.recipes.find((recipe) => recipe.id === id)
}

export const serve = createRouter

function context(app: App, recipe: RecipeBinding, caller: { issuer?: string }): CheckContext {
  return {
    recipeId: recipe.id,
    binding: { scope: recipe.scope },
    now: app.now(),
    secret(name: string) {
      if (caller.issuer === "weave") {
        throw new CheckError("operator token cannot read provider secrets", "blocked")
      }
      return app.secret(name)
    },
    store: app.store,
    clients: app.clients,
    http: { async get() { throw new Error("http client is not configured") } },
    async scope(path) {
      const document = await app.readScope(path)
      return { document: document as never, digest: scopeDigest(document) }
    },
    blocked: (message, detail) => new CheckError(message, "blocked", detail),
    failed: (message, detail) => new CheckError(message, "failed", detail),
    pending: (windowId) => new CheckError("pending", "pending", windowId),
  }
}
