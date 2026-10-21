import { createPublicKey, createVerify, type JsonWebKey } from "node:crypto"
import type { TokenClaims } from "./auth.ts"

export const actionsIssuer = "https://token.actions.githubusercontent.com"
export const actionsAudience = "https://stellarbridge.app/weave/automations"

type Header = { alg?: string; kid?: string }
type Claims = { iss?: string; aud?: string | string[]; exp?: number; nbf?: number; repository?: string; workflow?: string; workflow_ref?: string }

export async function actionsClaims(token: string, now: Date, loadKeys: (url: string) => Promise<{ keys?: JsonWebKey[] }>): Promise<TokenClaims | undefined> {
  const parts = token.split(".")
  if (parts.length !== 3) return undefined
  let header: Header
  let payload: Claims
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8")) as Header
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8")) as Claims
  } catch {
    return undefined
  }
  if (header.alg !== "RS256" || !header.kid) return undefined
  if (payload.iss !== actionsIssuer) return undefined
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud]
  if (!audiences.includes(actionsAudience)) return undefined
  const exp = Number(payload.exp)
  const nbf = payload.nbf === undefined ? now.getTime() / 1000 : Number(payload.nbf)
  if (!Number.isFinite(exp) || exp * 1000 < now.getTime() - 60_000) return undefined
  if (!Number.isFinite(nbf) || nbf * 1000 > now.getTime() + 60_000) return undefined
  const repository = payload.repository ?? ""
  const workflow = workflowFile(payload)
  if (!repository || !workflow) return undefined
  let keys: { keys?: JsonWebKey[] }
  try {
    keys = await loadKeys(`${actionsIssuer}/.well-known/jwks`)
  } catch {
    return undefined
  }
  const jwk = (keys.keys ?? []).find((key) => key.kid === header.kid)
  if (!jwk) return undefined
  const verifier = createVerify("RSA-SHA256")
  verifier.update(`${parts[0]}.${parts[1]}`)
  const ok = verifier.verify(createPublicKey({ key: jwk, format: "jwk" }), Buffer.from(parts[2], "base64url"))
  if (!ok) return undefined
  return { issuer: actionsIssuer, subject: workflow, repository, workflow }
}

function workflowFile(payload: Claims) {
  const match = /\/\.github\/workflows\/([^@]+)/.exec(payload.workflow_ref ?? "")
  if (match) return match[1]
  return payload.workflow ?? ""
}
