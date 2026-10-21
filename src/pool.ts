export function requirePooled(connectionString: string): string {
  const host = new URL(connectionString).hostname
  if (!host.includes("-pooler.")) {
    throw new Error("function runtime requires the pooled Neon connection")
  }
  return connectionString
}
