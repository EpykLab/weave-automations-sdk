import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import test from "node:test"
import { scopeDigest } from "../src/digest.ts"

test("scope digest matches jq -S -c piped to sha256sum", () => {
  const digest = scopeDigest({
    schema_version: 1,
    kind: "github_repository_scope",
    b: 1,
    a: [2, 1],
  })
  assert.equal(digest, "cff8adf446dc3d77b87fa6c201ab4a97d55bd540dda9136e65963bd3ad416811")
})

test("github repository scope matches validate-evidence-scope.sh", async () => {
  const scope = JSON.parse(await readFile(new URL("./fixtures/github-repositories.json", import.meta.url), "utf8"))
  assert.equal(scopeDigest(scope), "f3a1ff016882c22d36f9b4f3f96292098429458268d3a9fd9944fc76a23c894e")
})
