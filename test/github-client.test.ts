import assert from "node:assert/strict"
import test from "node:test"
import { githubClient } from "../src/github-client.ts"

test("the GitHub client follows link headers and treats a missing protection document as empty", async () => {
  const calls: string[] = []
  const original = globalThis.fetch
  globalThis.fetch = (async (url: string | URL) => {
    const target = String(url)
    calls.push(target)
    if (target.endsWith("/repos?per_page=1")) {
      return new Response(JSON.stringify([{ full_name: "EpykLab/stllr" }]), {
        headers: { link: `<https://api.github.com/orgs/EpykLab/repos?page=2>; rel="next"` },
      })
    }
    if (target.endsWith("page=2")) return new Response(JSON.stringify([{ full_name: "EpykLab/weave" }]))
    if (target.endsWith("/protection")) return new Response("missing", { status: 404 })
    return new Response("no", { status: 500 })
  }) as typeof fetch
  try {
    const client = githubClient("token")
    const repos = await client.paginate<{ full_name: string }>("/orgs/EpykLab/repos?per_page=1")
    assert.deepEqual(repos.map((repo) => repo.full_name), ["EpykLab/stllr", "EpykLab/weave"])
    assert.equal(await client.get("/repos/EpykLab/stllr/branches/master/protection", { allowMissing: true }), null)
    assert.equal(calls.length, 3)
  } finally {
    globalThis.fetch = original
  }
})
