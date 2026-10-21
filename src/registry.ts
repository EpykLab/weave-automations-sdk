import { securityInbox, offeringInventory, keyVaultAudit } from "./azure.ts"
import { auth0, cloudflare, elastic, flyApps, flyCerts, tigris, tls, valkey } from "./inventory.ts"
import { branchProtection, dependabot } from "./github.ts"
import { appDatabase, logShip, namespaces, networkIsolation, posture, reportJob, signin, workloads } from "./kubernetes.ts"
import { backupPosture } from "./neon.ts"
import { accountInventory, deliveryTest } from "./resend.ts"
import type { Action, Check } from "./types.ts"

export const checks: Check[] = [
  branchProtection, dependabot, backupPosture, offeringInventory, keyVaultAudit, securityInbox,
  auth0, cloudflare, valkey, flyApps, flyCerts, tigris, elastic, accountInventory, tls,
  posture, namespaces, workloads, networkIsolation, appDatabase, signin, reportJob, logShip,
]

export const actions: Action[] = [deliveryTest]

export function probe(id: string): Check | Action | undefined {
  return checks.find((item) => item.id === id) ?? actions.find((item) => item.id === id)
}
