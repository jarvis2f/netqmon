use crate::classifier::EntityMetadata;

pub(crate) fn application_candidates(
    application: &EntityMetadata,
    organization: Option<&EntityMetadata>,
) -> Vec<String> {
    let mut candidates = icon_candidates(application);
    if let Some(organization) = organization {
        candidates.extend(icon_candidates(organization));
    }
    dedupe(candidates)
}

pub(crate) fn organization_candidates(organization: &EntityMetadata) -> Vec<String> {
    dedupe(icon_candidates(organization))
}

fn icon_candidates(entity: &EntityMetadata) -> Vec<String> {
    entity
        .icon
        .domain
        .iter()
        .chain(entity.icon.fallback_domains.iter())
        .cloned()
        .collect()
}

fn dedupe(candidates: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    candidates
        .into_iter()
        .filter(|candidate| seen.insert(candidate.clone()))
        .collect()
}
