// TypeScript mirror of backend/app/schemas.py (AGENTS.md §4). Owner: P1.
// Keep in sync with schemas.py — change both together.

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export type RiskLevel =
  | 'low_risk'
  | 'suspicious'
  | 'high_risk'
  | 'confirmed_malicious'
  | 'inconclusive'

export type CheckName = 'url' | 'dns' | 'threat_intel' | 'tls' | 'headers' | 'message'

export interface Finding {
  id: string
  check: CheckName
  title: string
  severity: Severity
  evidence: string
  source: string
  impact?: string | null
  recommendation?: string | null
  authoritative: boolean
}

export interface CheckResult {
  check: CheckName
  status: 'ok' | 'error' | 'skipped'
  target?: string | null
  findings: Finding[]
  data: Record<string, unknown>
  limitations: string[]
  duration_ms: number
}

export interface Explanation {
  summary: string
  key_points: string[]
  recommendations: string[]
}

export interface ChainRecord {
  report_hash: string
  chain_report_id: number
  tx_hash: string
  network: string
  contract_address: string
}

export interface AnalysisReport {
  id: string
  input_type: 'url' | 'domain' | 'message'
  input: string
  normalized_target?: string | null
  created_at: string
  risk_level: RiskLevel
  risk_reasons: string[]
  coverage: number
  checks: CheckResult[]
  extracted_indicators: Record<string, string[]>
  explanation?: Explanation | null
  recommendations: string[]
  limitations: string[]
  related_report_ids: string[]
  chain?: ChainRecord | null
}

export interface VerifyResult {
  recomputed_hash: string
  onchain_hash?: string | null
  match: boolean
  tx_hash?: string | null
  block_timestamp?: number | null
  status: string // "verified" | "mismatch" | "untrusted_submitter" | "registered_late" | "not_registered"
  chain_status?: string | null // on-chain record: active / disputed / revised
  submitter?: string | null
  explorer_url?: string | null // block-explorer link for the registration tx
  detail?: string | null // plain-English explanation of the result — show this to the user
}

export interface RelatedReport {
  report_id: string
  shared_indicators: string[]
  label?: string | null
  risk_level?: RiskLevel | null
  created_at?: string | null
  relation: 'same_site' | 'campaign' // same website checked again vs a different site/message sharing details
}

export interface CorrelationResult {
  related: RelatedReport[]
}
