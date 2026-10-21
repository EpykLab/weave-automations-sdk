import type { ActionRow, ActionStore } from "./types.ts"

export function memoryStore(now: Date): ActionStore {
  const rows = new Map<string, ActionRow>()
  const key = (row: Pick<ActionRow, "recipeId" | "action" | "windowId">) =>
    `${row.recipeId}\0${row.action}\0${row.windowId}`
  return {
    window(_recipeId, _action, everyMs) {
      const start = Math.floor(now.getTime() / everyMs) * everyMs
      return new Date(start).toISOString().replace(".000Z", "Z")
    },
    async put(row) {
      const id = key(row)
      const existing = rows.get(id)
      if (existing) return existing
      rows.set(id, row)
      return row
    },
    async current(recipeId, action) {
      const matches = [...rows.values()].filter(
        (row) => row.recipeId === recipeId && row.action === action && row.status === "accepted",
      )
      matches.sort((a, b) => (a.windowId < b.windowId ? 1 : -1))
      return matches[0] ?? null
    },
    async markObserved(recipeId, action) {
      for (const [id, row] of rows) {
        if (row.recipeId === recipeId && row.action === action && row.status === "accepted") {
          rows.set(id, { ...row, status: "observed" })
        }
      }
    },
  }
}
