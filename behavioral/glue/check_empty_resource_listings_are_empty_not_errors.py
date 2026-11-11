"""empty-resource-listings-are-empty-not-errors."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "empty-resource-listings-are-empty-not-errors"
GROUP = 'listing'
SERVICES = ['glue']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """List/Get collection APIs return empty collections (not errors) and honour not-found keys."""
    glue = ctx.client("glue")
    # Every one of these must return a well-formed (possibly empty) collection.
    # NOTE: DevEndpoints APIs (get_dev_endpoints/list_dev_endpoints/
    # batch_get_dev_endpoints) are intentionally excluded -- AWS has disabled
    # the DevEndpoints service, so those operations now raise
    # AccessDeniedException ("operation is currently disabled") rather than
    # returning an empty collection.
    transforms = glue.get_ml_transforms()["Transforms"]
    assert isinstance(transforms, list), f"get_ml_transforms must return a list, got {transforms!r}"
    transform_ids = glue.list_ml_transforms()["TransformIds"]
    assert isinstance(transform_ids, list), f"list_ml_transforms must return a list, got {transform_ids!r}"
    blueprints = glue.list_blueprints()["Blueprints"]
    assert isinstance(blueprints, list), f"list_blueprints must return a list, got {blueprints!r}"
    crawler_names = glue.list_crawlers()["CrawlerNames"]
    assert isinstance(crawler_names, list), f"list_crawlers must return a list, got {crawler_names!r}"
    crawlers = glue.get_crawlers()["Crawlers"]
    assert isinstance(crawlers, list), f"get_crawlers must return a list, got {crawlers!r}"
    classifiers = glue.get_classifiers()["Classifiers"]
    assert isinstance(classifiers, list), f"get_classifiers must return a list, got {classifiers!r}"
    connections = glue.get_connections()["ConnectionList"]
    assert isinstance(connections, list), f"get_connections must return a list, got {connections!r}"
    registries = glue.list_registries()["Registries"]
    assert isinstance(registries, list), f"list_registries must return a list, got {registries!r}"
    security_configs = glue.get_security_configurations()["SecurityConfigurations"]
    assert isinstance(security_configs, list), (
        f"get_security_configurations must return a list, got {security_configs!r}"
    )
    rulesets = glue.list_data_quality_rulesets()["Rulesets"]
    assert isinstance(rulesets, list), f"list_data_quality_rulesets must return a list, got {rulesets!r}"
    workflows = glue.list_workflows()["Workflows"]
    assert isinstance(workflows, list), f"list_workflows must return a list, got {workflows!r}"
    trigger_names = glue.list_triggers()["TriggerNames"]
    assert isinstance(trigger_names, list), f"list_triggers must return a list, got {trigger_names!r}"
    sessions = glue.list_sessions()["Sessions"]
    assert isinstance(sessions, list), f"list_sessions must return a list, got {sessions!r}"
    usage_profiles = glue.list_usage_profiles()["Profiles"]
    assert isinstance(usage_profiles, list), f"list_usage_profiles must return a list, got {usage_profiles!r}"
    dq_results = glue.list_data_quality_results()["Results"]
    assert isinstance(dq_results, list), f"list_data_quality_results must return a list, got {dq_results!r}"
    dq_recs = glue.list_data_quality_rule_recommendation_runs()["Runs"]
    assert isinstance(dq_recs, list), (
        f"list_data_quality_rule_recommendation_runs must return a list, got {dq_recs!r}"
    )
    dq_evals = glue.list_data_quality_ruleset_evaluation_runs()["Runs"]
    assert isinstance(dq_evals, list), (
        f"list_data_quality_ruleset_evaluation_runs must return a list, got {dq_evals!r}"
    )
    catalogs = glue.get_catalogs()["CatalogList"]
    assert isinstance(catalogs, list), f"get_catalogs must return a list, got {catalogs!r}"

    # Account-level catalog settings are always readable.
    enc = glue.get_data_catalog_encryption_settings()["DataCatalogEncryptionSettings"]
    assert isinstance(enc, dict), f"expected catalog encryption settings dict, got {enc!r}"

    # Batch reads for unknown names report them as not-found rather than erroring.
    bp = glue.batch_get_blueprints(Names=["does-not-exist-blueprint"])
    assert bp["MissingBlueprints"] == ["does-not-exist-blueprint"], (
        f"unknown blueprint must be reported as missing: {bp}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
