import { Pool } from "pg"
import type { ActionRow, ActionStore } from "./types.ts"

const migrationSQL = `create table if not exists weave_actions (
  recipe_id text not null,
  action text not null,
  window_id text not null,
  status text not null,
  deadline timestamptz not null,
  primary key (recipe_id, action, window_id)
);
`

export interface Querier {
  query(sql: string, params?: unknown[]): Promise<{ rows: Array<Record<string, unknown>> }>
}

export async function migrate(db: Querier) {
  await db.query(migrationSQL)
}

export function postgresStore(db: Querier, now: Date): ActionStore {
  return {
    window(_recipeId, _action, everyMs) {
      const start = Math.floor(now.getTime() / everyMs) * everyMs
      return new Date(start).toISOString().replace(".000Z", "Z")
    },
    async put(row) {
      const inserted = await db.query(
        `insert into weave_actions (recipe_id, action, window_id, status, deadline)
         values ($1, $2, $3, $4, $5)
         on conflict (recipe_id, action, window_id) do nothing
         returning recipe_id, action, window_id, status, deadline`,
        [row.recipeId, row.action, row.windowId, row.status, row.deadline],
      )
      const stored = inserted.rows[0] ?? (await db.query(
        `select recipe_id, action, window_id, status, deadline
         from weave_actions where recipe_id = $1 and action = $2 and window_id = $3`,
        [row.recipeId, row.action, row.windowId],
      )).rows[0]
      return mapRow(stored)
    },
    async current(recipeId, action) {
      const result = await db.query(
        `select recipe_id, action, window_id, status, deadline
         from weave_actions
         where recipe_id = $1 and action = $2 and status = 'accepted'
         order by window_id desc
         limit 1`,
        [recipeId, action],
      )
      return result.rows[0] ? mapRow(result.rows[0]) : null
    },
    async markObserved(recipeId, action) {
      await db.query(
        `update weave_actions set status = 'observed' where recipe_id = $1 and action = $2 and status = 'accepted'`,
        [recipeId, action],
      )
    },
  }
}

export function connectPostgres(connectionString: string) {
  const ssl = connectionString.includes("sslmode=require") ? { rejectUnauthorized: false } : false
  const pool = new Pool({ connectionString, ssl })
  pool.on("error", () => undefined)
  return pool
}

function mapRow(row: Record<string, unknown>): ActionRow {
  const deadline = row.deadline instanceof Date ? row.deadline.toISOString() : String(row.deadline)
  return {
    recipeId: String(row.recipe_id),
    action: String(row.action),
    windowId: String(row.window_id),
    status: row.status === "observed" ? "observed" : "accepted",
    deadline,
  }
}
