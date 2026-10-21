import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"

const root = fileURLToPath(new URL("../", import.meta.url))
const temporary = mkdtempSync(path.join(tmpdir(), "weave-package-"))
const npm = process.platform === "win32" ? "npm.cmd" : "npm"
const manifest = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"))

try {
  const packResult = JSON.parse(execFileSync(npm, ["pack", "--json", "--pack-destination", temporary], {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  }))
  const packed = Array.isArray(packResult) ? packResult[0] : packResult[manifest.name]
  assert(packed, "npm pack did not return metadata for " + manifest.name)
  const files = packed.files.map((file) => file.path)
  for (const required of ["LICENSE", "README.md", "dist/index.js", "dist/index.d.ts"]) {
    assert(files.includes(required), `Missing ${required}`)
  }
  assert(!files.some((file) => file.startsWith("test/") || file.startsWith("src/")), "Package contains tests or raw source")

  writeFileSync(path.join(temporary, "package.json"), JSON.stringify({ private: true, type: "module" }))
  execFileSync(npm, ["install", "--ignore-scripts", "--no-audit", "--no-fund", path.join(temporary, packed.filename)], {
    cwd: temporary,
    stdio: "inherit",
  })
  const imports = Object.keys(manifest.exports).map((entry) => manifest.name + (entry === "." ? "" : entry.slice(1)))
  writeFileSync(path.join(temporary, "smoke.mjs"), `
    import assert from "node:assert/strict"
    for (const name of ${JSON.stringify(imports)}) {
      assert(Object.keys(await import(name)).length > 0, name)
      console.log("PASS import", name)
    }
    const { defineCheck, scopeDigest } = await import(${JSON.stringify(manifest.name)})
    const check = defineCheck({ id: "smoke", secrets: [], scopeKind: "smoke", async run() { return { compliant: true } } })
    assert.deepEqual(await check.run({}), { compliant: true })
    assert.equal(scopeDigest({ a: 1 }), scopeDigest({ a: 1 }))
  `)
  execFileSync(process.execPath, ["smoke.mjs"], { cwd: temporary, stdio: "inherit" })

  writeFileSync(path.join(temporary, "consumer.mts"), `
    ${imports.map((name, index) => `import * as entry${index} from ${JSON.stringify(name)}; void entry${index}`).join("\n")}
    import { defineCheck, type Check } from ${JSON.stringify(manifest.name)}
    const check: Check = defineCheck({ id: "smoke", secrets: [], scopeKind: "smoke", async run() { return { compliant: true } } })
    void check
  `)
  execFileSync(process.execPath, [path.join(root, "node_modules/typescript/bin/tsc"),
    "--noEmit", "--strict", "--target", "ES2022", "--module", "NodeNext",
    "--moduleResolution", "NodeNext", "--typeRoots", path.join(root, "node_modules/@types"), "consumer.mts"], {
    cwd: temporary,
    stdio: "inherit",
  })
  console.log("PASS package contents and TypeScript consumer")
} finally {
  rmSync(temporary, { recursive: true, force: true })
}
