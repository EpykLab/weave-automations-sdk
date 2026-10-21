import { defineCheck } from "../../src/define.ts"

export default defineCheck({
  id: "acme.widget-health",
  secrets: [],
  scopeKind: "example",
  async run(ctx) {
    const scope = await ctx.scope<{ ok: boolean }>(ctx.binding.scope)
    return { compliant: true, scope_digest: scope.digest, widget: "WIDGET_BODY" }
  },
})
