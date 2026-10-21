import type { Caller } from "./types.ts"

export interface AccessSubject {
  name: string
  issuer: string
  repository?: string
  workflow?: string
  allow: string[]
}

export interface TokenClaims {
  issuer: string
  subject: string
  repository?: string
  workflow?: string
}

export function accessCaller(subjects: AccessSubject[], claims: TokenClaims): Caller | undefined {
  const match = subjects.find((item) => {
    if (item.issuer !== claims.issuer) return false
    if (item.issuer === "https://token.actions.githubusercontent.com") {
      return item.repository === claims.repository && item.workflow === claims.workflow
    }
    return item.name === claims.subject
  })
  if (!match) return undefined
  return {
    subject: match.name,
    issuer: match.issuer,
    allows(recipeId, operation) {
      return match.allow.some((scope) => allows(scope, recipeId, operation))
    },
  }
}

function allows(scope: string, recipeId: string, operation: "run" | "act") {
  const match = /^recipe:(\*|[A-Za-z0-9][A-Za-z0-9._-]*):(run|act)$/.exec(scope)
  if (!match || match[2] !== operation) return false
  return match[1] === "*" || match[1] === recipeId
}
