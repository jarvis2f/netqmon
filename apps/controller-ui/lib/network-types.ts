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
