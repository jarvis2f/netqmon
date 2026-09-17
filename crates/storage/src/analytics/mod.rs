#[cfg(feature = "analytics-clickhouse")]
pub mod clickhouse;
#[cfg(feature = "analytics-duckdb")]
pub mod duckdb;
mod models;

pub use models::{
    AnalyticsBatch, AnalyticsFlow, AnalyticsFlowIdentity, AnalyticsOverview, AnalyticsQueryPlan,
    AnalyticsQuerySegment, AnalyticsResolution, AnalyticsSummary, ApplyBatchResult, FlowPage,
    FlowQuery, FlowSort, GeoTraffic, SummaryQuery, TrafficBreakdown, TrafficBreakdownQuery,
    TrafficDelta, TrafficDimension, TrafficPoint, TrafficQuery, resolution_for_range,
};

use crate::{RetentionPolicy, StorageResult};

/// Historical traffic and flow storage contract.
///
/// Implementations own all backend-specific SQL and expose the same query and
/// retry semantics to the collector.
pub trait AnalyticsStore: Send {
    /// # Errors
    /// Returns an error if the analytics backend cannot run the query.
    fn overview(&self, from: u64, to: u64) -> StorageResult<AnalyticsOverview>;
    /// # Errors
    /// Returns an error if the batch cannot be applied.
    fn apply_batch(&mut self, batch: &AnalyticsBatch) -> StorageResult<ApplyBatchResult>;
    /// Applies several outbox batches in one backend operation. Backends may
    /// override this to use one transaction for the complete slice.
    ///
    /// # Errors
    /// Returns an error if the analytics backend cannot apply the batches.
    fn apply_batches(
        &mut self,
        batches: &[AnalyticsBatch],
    ) -> StorageResult<Vec<ApplyBatchResult>> {
        batches
            .iter()
            .map(|batch| self.apply_batch(batch))
            .collect()
    }
    /// # Errors
    /// Returns an error if the analytics backend cannot run the query.
    fn traffic_series(&self, query: &TrafficQuery) -> StorageResult<Vec<TrafficPoint>>;
    /// # Errors
    /// Returns an error if the analytics backend cannot run the query.
    fn traffic_breakdown(
        &self,
        query: &TrafficBreakdownQuery,
    ) -> StorageResult<Vec<TrafficBreakdown>>;
    /// # Errors
    /// Returns an error if the analytics backend cannot run the query.
    fn flows(&self, query: &FlowQuery) -> StorageResult<FlowPage>;
    /// Reads the latest stored version for one flow identity.
    ///
    /// # Errors
    /// Returns an error if the analytics backend cannot read the flow version.
    fn flow_by_id(&self, gateway_id: &str, flow_id: &str) -> StorageResult<Option<AnalyticsFlow>>;
    /// Finds the latest version from the stable tuple and first-seen time.
    ///
    /// # Errors
    /// Returns an error if the analytics backend cannot read the flow version.
    fn flow_by_tuple(
        &self,
        identity: &AnalyticsFlowIdentity,
    ) -> StorageResult<Option<AnalyticsFlow>>;
    /// # Errors
    /// Returns an error if the analytics backend cannot run the query.
    fn application_summary(&self, query: &SummaryQuery) -> StorageResult<Vec<AnalyticsSummary>>;
    /// # Errors
    /// Returns an error if the analytics backend cannot run the query.
    fn organization_summary(&self, query: &SummaryQuery) -> StorageResult<Vec<AnalyticsSummary>>;
    /// # Errors
    /// Returns an error if the analytics backend cannot run the query.
    fn protocol_summary(&self, query: &SummaryQuery) -> StorageResult<Vec<AnalyticsSummary>>;
    /// # Errors
    /// Returns an error if the analytics backend cannot run the query.
    fn transport_protocol_summary(
        &self,
        query: &SummaryQuery,
    ) -> StorageResult<Vec<AnalyticsSummary>>;
    /// # Errors
    /// Returns an error if the analytics backend cannot run the query.
    fn category_summary(&self, query: &SummaryQuery) -> StorageResult<Vec<AnalyticsSummary>>;
    /// # Errors
    /// Returns an error if the analytics backend cannot run the query.
    fn domain_summary(&self, query: &SummaryQuery) -> StorageResult<Vec<AnalyticsSummary>>;
    /// # Errors
    /// Returns an error if the analytics backend cannot run the query.
    fn destination_summary(&self, query: &SummaryQuery) -> StorageResult<Vec<AnalyticsSummary>>;
    /// # Errors
    /// Returns an error if the analytics backend cannot run the query.
    fn client_traffic(&self, query: &SummaryQuery) -> StorageResult<Vec<AnalyticsSummary>>;
    /// # Errors
    /// Returns an error if the analytics backend cannot run the query.
    fn geo_traffic(&self, query: &SummaryQuery) -> StorageResult<Vec<GeoTraffic>>;
    /// # Errors
    /// Returns an error if the analytics backend cannot calculate the ratio.
    fn unknown_ratio(&self, since: u64) -> StorageResult<f64>;
    /// # Errors
    /// Returns an error if rollups cannot be written.
    fn rollup(&mut self, now: u64) -> StorageResult<u64>;
    /// # Errors
    /// Returns an error if retention cleanup cannot be completed.
    fn run_retention(&mut self, now: u64, policy: RetentionPolicy) -> StorageResult<()>;
    /// # Errors
    /// Returns an error if the backend cannot report its database size.
    fn database_size_bytes(&self) -> StorageResult<u64>;
    fn backend_name(&self) -> &'static str;
}
