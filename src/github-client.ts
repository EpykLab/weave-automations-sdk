import { CheckError, type GitHubClient } from "./types.ts"

const api = "https://api.github.com"

export function githubClient(token: string): GitHubClient {
  return {
    async get(path, options) {
      const response = await fetch(api + path, { headers: headers(token) })
      if (response.status === 404 && options?.allowMissing) return null
      if (!response.ok) throw githubStatus("GET", path, response.status)
      return response.json() as Promise<never>
    },
    async paginate(path) {
      const items: unknown[] = []
      let next: string | undefined = path.startsWith("http") ? path : api + path
      while (next) {
        const response = await fetch(next, { headers: headers(token) })
        if (!response.ok) throw githubStatus("GET", nextPath(next), response.status)
        const page = await response.json()
        if (!Array.isArray(page)) throw new Error(`github GET ${nextPath(next)} did not return a list`)
        items.push(...page)
        next = linkNext(response.headers.get("link"))
      }
      return items as never
    },
  }
}

function githubStatus(method: string, path: string, status: number) {
  const message = `github ${method} ${path} returned ${status}`
  if (status === 401 || status === 403) return new CheckError(message, "blocked", { status, path })
  return new Error(message)
}

function headers(token: string) {
  return {
    accept: "application/vnd.github+json",
    authorization: `Bearer ${token}`,
    "user-agent": "weave-automations",
    "x-github-api-version": "2022-11-28",
  }
}

function linkNext(header: string | null) {
  if (!header) return undefined
  for (const part of header.split(",")) {
    const match = /<([^>]+)>;\s*rel="next"/.exec(part)
    if (match) return match[1]
  }
  return undefined
}

function nextPath(url: string) {
  return url.startsWith(api) ? url.slice(api.length) : url
}
