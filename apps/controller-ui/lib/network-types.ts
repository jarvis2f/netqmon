export interface ApplicationSummary {
  application_id: string;
  category_id: string;
  name?: string | null;
  organization_id?: string;
  organization_name?: string | null;
  icon?: IconMetadata | null;
  upload_bytes: number;
  download_bytes: number;
  packets: number;
  flow_count: number;
  last_seen: number;
  client_count: number;
  confidence?: number;
  classifier_reason?: string;
  domain_count?: number;
  destination_count?: number;
  observed_protocols?: Array<{ id: string; flows: number }>;
}

export interface IconMetadata {
  domain?: string | null;
  fallback_domains?: string[];
  local_fallback?: string | null;
}

export interface ClientSummary {
  id: number;
  mac: string;
  ip?: string | null;
  name: string;
  vendor: string | null;
  identity?: DeviceIdentity | null;
  last_seen: number;
  last_traffic_seen?: number | null;
  upload_bytes: number;
  download_bytes: number;
  flow_count: number;
  self_host_application?: SelfHostApplication | null;
}

export interface SelfHostApplication {
  application_id: string;
  confidence: number;
  source?: string | null;
  last_seen?: number | null;
  role: "server";
}

export interface DeviceIdentity {
  vendor: string | null;
  device_type: string | null;
  os_family: string | null;
  model: string | null;
  confidence: "unknown" | "low" | "medium" | "high" | (string & {});
  vendor_confidence?: number;
  device_type_confidence?: number;
  os_confidence?: number;
  model_confidence?: number;
  private_mac?: boolean;
  evidence?: Array<Record<string, string | number | boolean | null>>;
}

export interface IconCacheStats {
  entry_count: number;
  weighted_size_bytes: number;
  capacity_bytes: number;
  positive_ttl_seconds: number;
  negative_ttl_seconds: number;
}

export interface DomainSummary {
  domain: string;
  upload_bytes: number;
  download_bytes: number;
  packets: number;
  flow_count: number;
  last_seen: number;
}

export interface DestinationSummary {
  remote_ip: string;
  domain: string | null;
  application?: string | null;
  country_code: string | null;
  country_name: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: number | null;
  organization: string | null;
  upload_bytes: number;
  download_bytes: number;
  packets: number;
  flow_count: number;
  client_count: number;
  last_seen: number;
  application_name?: string | null;
}

export interface GeoSummary {
  enabled: boolean;
  top_countries: Array<{
    country_code: string;
    country_name: string;
    bytes: number;
  }>;
  top_asns: Array<{ asn: number; organization: string; bytes: number }>;
  country_distribution: Array<{
    country_code: string;
    country_name: string;
    bytes: number;
  }>;
}

export interface FlowSummary {
  id: string;
  client_id?: number | null;
  client_name?: string;
  client_mac?: string | null;
  client_identity?: {
    device_type?: string | null;
    model?: string | null;
    vendor?: string | null;
    os_family?: string | null;
  } | null;
  client_ip: string;
  client_port: number;
  remote_ip: string;
  remote_port: number;
  protocol: number;
  direction: number;
  domain: string | null;
  organization?: string;
  application: string;
  application_name?: string | null;
  icon?: IconMetadata | null;
  category: string;
  traffic_role?: string;
  protocol_id?: string;
  organization_confidence?: number;
  application_confidence?: number;
  protocol_confidence?: number;
  confidence: number;
  reason?: string;
  evidence?: string | null;
  upload_bytes: number;
  download_bytes: number;
  packets: number;
  started_at: number;
  last_seen: number;
  ended_at: number | null;
  scope: "internet" | "internal" | "tunnel" | "unknown";
  path_type: "forwarded" | "internal" | "tunnel" | "unknown";
  nat: "none" | "snat" | "dnat" | "both" | "unknown";
  source_segment: string;
  destination_segment: string;
}

export type InsightCategory =
  | "device"
  | "traffic"
  | "classification"
  | "dns"
  | "protocol"
  | "capture"
  | "destination"
  | "network_quality"
  | "connectivity"
  | "routing"
  | (string & {});

export interface Insight {
  id: string;
  category: InsightCategory;
  code: string;
  severity: "info" | "notice" | "warning";
  time: number;
  source: string;
  affected_client: {
    id: number | null;
    name: string;
    mac?: string | null;
    ip?: string | null;
  } | null;
  params: Record<string, unknown>;
  evidence: Record<string, unknown>;
  fingerprint?: string | null;
  status?: string | null;
  first_seen?: number | null;
  last_seen?: number | null;
  occurrences?: number | null;
  confidence?: number | null;
}

export interface ApiEnvelope<T> {
  schema_version: number;
  data: T;
  pagination?: {
    limit: number;
    offset?: number;
    total?: number;
    next_cursor?: string | null;
    sort?: string;
    order?: string;
  } | null;
  error?: { code?: string; message?: string };
}

export interface LicenseStatus {
  installation_id: string;
  activated: boolean;
  edition: "community" | "pro" | string;
  license_status: string;
  rule_version?: string | null;
  lease_valid_until?: number | null;
  last_success_at?: number | null;
  last_error?: string | null;
}

export type PolicyActionKind = "block" | "allow" | "limit";
export type PolicyWeekday =
  "mon" | "tue" | "wed" | "thu" | "fri" | "sat" | "sun";

export interface PolicyScheduleWindow {
  days: PolicyWeekday[];
  start: string;
  end: string;
}

export interface PolicySpecV1 {
  schema_version: 1;
  gateway_id: string;
  name: string;
  description: string;
  enabled: boolean;
  priority: number;
  selectors: {
    clients: string[];
    applications: string[];
    categories: string[];
    min_application_confidence: number;
  };
  network: { scope: "internet" | "agent"; direction: "both" };
  action: {
    type: PolicyActionKind;
    download_bps: number | null;
    upload_bps: number | null;
  };
  schedule: null | { timezone: string; windows: PolicyScheduleWindow[] };
}

export interface PolicyRecord {
  id: string;
  created_at_ms: number;
  updated_at_ms: number;
  version: number;
  spec: PolicySpecV1;
  execution_status: "unsupported" | "not_deployed" | string;
  execution_reason_code: string | null;
  execution_message: string | null;
  execution_details?: PolicyResultDetails | null;
}

export interface PolicyResultDetails {
  clients: Array<{
    mac: string;
    effective_upload_bps: number | null;
    effective_download_bps: number | null;
  }>;
  controlled_interfaces: string[];
  qdisc: string | null;
  mark_conflict_code: string | null;
}

export interface PolicyTrafficDirectionMetrics {
  interface: string;
  bytes: number | null;
  packets: number | null;
  drops: number | null;
  overlimits: number | null;
}

export interface PolicyTrafficMetrics {
  policy_id: string;
  mac: string;
  upload: PolicyTrafficDirectionMetrics | null;
  download: PolicyTrafficDirectionMetrics | null;
}

export interface PolicyEvent {
  event_id: number;
  action: string;
  actor_user_id: string;
  before: PolicySpecV1 | null;
  after: PolicySpecV1 | null;
  revision: number;
  created_at_ms: number;
}

export interface PolicyOption {
  id: string;
  name: string;
  mac?: string;
  gateway_id?: string;
}

export interface PolicyPage {
  items: PolicyRecord[];
  total: number;
  desired_revision: number;
  applied_revision: number;
  capabilities: PolicyCapabilities;
}

export interface PolicyDetail {
  policy: PolicyRecord;
  events: PolicyEvent[];
  desired_revision: number;
  applied_revision: number;
}

export interface PolicyDeployment {
  gateway_id: string;
  desired_revision: number;
  delivered_revision?: number;
  delivery_status?: string;
  delivered_at_ms?: number | null;
  acknowledged_revision?: number;
  acknowledged_status?: string | null;
  applied_revision: number;
  status: string;
  capabilities: PolicyCapabilities;
  policies: Array<{
    policy_id: string;
    status: string;
    reason_code: string | null;
    message: string | null;
    details?: PolicyResultDetails | null;
    traffic_metrics?: PolicyTrafficMetrics[];
  }>;
  last_error_code: string | null;
  last_error_message: string | null;
  last_reported_at_ms: number | null;
  last_heartbeat_at_ms: number | null;
  agent_connected: boolean;
}

export interface PolicyCapabilities {
  enforcement_supported: boolean;
  status: string;
  reason: string;
  client_block: string;
  client_limit: string;
  application_block: string;
  application_limit: string;
}

export interface PolicyPreviewRequest {
  gateway_id: string;
  client_mac: string;
  application_id: string;
  category_id: string;
  application_confidence: number;
  scope: "internet";
  at_ms: number;
}

export interface PolicyPreviewMatch {
  policy_id: string;
  name: string;
  action: PolicyActionKind;
  priority: number;
  selected: boolean;
}

export interface PolicyPreviewLimit {
  policy_id: string;
  name: string;
  download_bps: number | null;
  upload_bps: number | null;
  status: string;
  reason_code: string | null;
}

export interface PolicyPreviewResult {
  matched_policies: PolicyPreviewMatch[];
  selected_block_verdict: string;
  active_limits: PolicyPreviewLimit[];
  explanation: string;
  unsupported_reasons: string[];
}

export interface PolicyValidation {
  normalized_spec: PolicySpecV1 | null;
  errors: Array<{ path: string; code: string; message: string }>;
  warnings: string[];
  valid: boolean;
}

export interface RetentionPolicy {
  flow_sessions_days: number;
  dns_days: number;
  minute_days: number;
  hour_days: number;
  day_days: number;
}

export interface DiagnosticsInfo {
  collector_version: string;
  db_backend: string;
  db_size_bytes: number;
  gateway: {
    id: string;
    name: string;
    agent_version: string;
    kernel_version: string;
    openwrt_version: string;
    last_seen: number;
  } | null;
  active_flows: number;
  unknown_ratio: number;
  retention: RetentionPolicy;
  geo_enabled: boolean;
  classification?: DiagnosticsClassification;
  sampling?: SamplingDiagnostics;
  topology?: TopologySummary | null;
}

export interface TopologySegment {
  subnet: string;
  interface: string;
  role: string;
  confidence: number;
}

export interface TopologySummary {
  topology_mode: string;
  agent_addresses: string[];
  upstream_gateway: string;
  segments: TopologySegment[];
  nat_status: string;
  attach_backend: string;
  attach_order: string;
  ipv4_coverage: string;
  ipv6_coverage: string;
  icmp_redirect: string;
  software_flow_offload: string;
  hardware_flow_offload: string;
  topology_warnings: string[];
  confidence: number;
  capture_interface: string;
}

export interface RuleStats {
  application_count: number;
  selfhost_application_count: number;
  client_count: number;
  protocol_count: number;
  rule_version: string;
  updated_at_unix_ms: number;
}

export interface RuleReloadResult extends RuleStats {
  reloaded_at: number;
}

export interface DiagnosticsClassification {
  classifier_version?: string | null;
  stats?: RuleStats | null;
  availability: string;
  last_error?: string | null;
}

export interface GeoDatabaseItem {
  filename: string;
  installed: boolean;
  database_type?: string | null;
  build_epoch?: number | null;
  build_date?: string | null;
  file_size_bytes: number;
  last_modified_unix_s?: number | null;
  record_count?: number | null;
  source_url: string;
}

export interface GeoDatabaseStatus {
  enabled: boolean;
  directory: string;
  databases: GeoDatabaseItem[];
  attribution: string;
}

export interface GeoUpdateResult {
  success: boolean;
  message: string;
  updated_files: string[];
  status: GeoDatabaseStatus;
}

export interface SamplingDiagnostics {
  engine: string;
  enabled: boolean;
  available: boolean;
  window_seconds: number;
  configs: Array<{
    gateway_id: string;
    enabled: boolean;
    max_bytes_per_flow: number;
    max_packets_per_direction: number;
    max_bytes_per_packet: number;
  }>;
  sample_count: number;
  packet_count: number;
  sampled_flows: number;
  sample_bytes: number;
  average_sample_bytes: number;
  p95_sample_bytes: number;
  max_sample_bytes: number;
  dpi_success_rate: number;
  sample_drops: number;
  sample_drop_rate: number;
  new_flows: number;
  new_flows_per_second: number;
  network_bytes: number;
  bandwidth_kbps: number;
  traffic_ratio: number | null;
  theoretical_max_kbps: number;
  impact: "Low" | "Moderate" | "High" | null;
}
