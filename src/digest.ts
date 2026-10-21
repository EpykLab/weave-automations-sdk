import { createHash } from "node:crypto"

// Matches `jq -S -c . FILE | sha256sum`, including jq's trailing newline.
export function scopeDigest(value: unknown): string {
  return createHash("sha256").update(canonical(value) + "\n").digest("hex")
}

function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`
  if (value !== null && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
      a < b ? -1 : a > b ? 1 : 0,
    )
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`
  }
  return JSON.stringify(value)
}
