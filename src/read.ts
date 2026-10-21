import type { CheckContext } from "./types.ts"

export async function providerPayload<T>(ctx: CheckContext, read: () => Promise<T>): Promise<T> {
  if (ctx.clients.payload) return await ctx.clients.payload(ctx.recipeId) as T
  return read()
}
