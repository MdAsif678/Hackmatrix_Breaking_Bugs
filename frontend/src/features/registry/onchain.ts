// Independent verification in the visitor's own browser. Owner: P1 (used by P4's Verify page).
// The browser reads the seal straight from the ThreatRegistry contract on Ethereum Sepolia through a public node
// (no TrustLens server involved), recomputes the report's SHA-256 fingerprint itself, and checks the same three
// conditions as the backend. If TrustLens's server lied about a verdict, this would show it.

export const SEPOLIA = {
  rpc: 'https://ethereum-sepolia-rpc.publicnode.com',
  contract: '0x089F4b08bcDBDEA5e3328D38676A63017266cb2e',
  // The official TrustLens wallet: only seals from this address count (contracts/deployments/sepolia.json).
  official: '0xf4f0a75a18b6F88d04F8564BF472E1EBDAC61256',
  windowHours: 24,
}

const GET_REPORT = '0x4e7f9b19' // first 4 bytes of keccak256("getReport(uint256)")

export type OnchainRecord = { hash: string; submitter: string; timestamp: number; status: number }

/** getReport(id) through eth_call: (bytes32 hash, address submitter, uint256 timestamp, string, uint8 status, uint256). */
export async function readSeal(chainReportId: number): Promise<OnchainRecord> {
  const data = GET_REPORT + chainReportId.toString(16).padStart(64, '0')
  const res = await fetch(SEPOLIA.rpc, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: SEPOLIA.contract, data }, 'latest'] }),
  })
  const body = await res.json()
  if (body.error || typeof body.result !== 'string' || body.result.length < 2 + 64 * 6) {
    throw new Error(body.error?.message || 'The blockchain node returned no record')
  }
  const word = (i: number) => body.result.slice(2 + i * 64, 2 + (i + 1) * 64)
  return {
    hash: '0x' + word(0),
    submitter: '0x' + word(1).slice(24),
    timestamp: parseInt(word(2), 16),
    status: parseInt(word(4), 16),
  }
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text))
  return '0x' + [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}
