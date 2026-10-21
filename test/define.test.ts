import assert from "node:assert/strict"
import test from "node:test"
import { bindCheck, defineCheck } from "../src/define.ts"

test("a custom module is rejected when its exported id does not match the binding", () => {
  const check = defineCheck({
    id: "custom.other",
    secrets: [],
    scopeKind: "example",
    async run() { return {} },
  })
  assert.throws(() => bindCheck("custom.expected", check), /custom.expected/)
})
