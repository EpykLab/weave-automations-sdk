import { bindCheck } from "./define.ts"
import type { Check } from "./types.ts"

export async function loadCheck(href: string, expected: string): Promise<Check> {
  const loaded = await import(href) as { default?: Check }
  const check = loaded.default
  if (!check || typeof check.run !== "function" || typeof check.id !== "string") {
    throw new Error(`module ${expected} does not default-export a check`)
  }
  return bindCheck(expected, check)
}
