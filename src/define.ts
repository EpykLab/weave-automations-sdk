import type { Action, Check } from "./types.ts"

export function defineCheck(check: Check): Check {
  return check
}

export function bindCheck(expected: string, check: Check): Check {
  if (check.id !== expected) {
    throw new Error(`probe ${expected} does not match module export ${check.id}`)
  }
  return check
}

export function defineAction(action: Action): Action {
  return action
}
