"""batch-get-aggregate-resource-config-nonexistent-aggregator-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-get-aggregate-resource-config-nonexistent-aggregator-rejected"
GROUP = "error-semantics"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BatchGetAggregateResourceConfig on a nonexistent aggregator fails with
    NoSuchConfigurationAggregatorException; the same identifier against a real aggregator succeeds
    and reports the never-discovered resource as unprocessed."""
    config = ctx.client("config")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    identifier = {
        "ResourceId": ctx.unique_name("sim2real-bgarc-res-"),
        "ResourceType": "AWS::EC2::Instance",
        "SourceAccountId": account_id,
        "SourceRegion": ctx.region,
    }
    bogus_aggregator = ctx.unique_name("sim2real-noagg-")

    code, code_message = _error(
        lambda: config.batch_get_aggregate_resource_config(
            ConfigurationAggregatorName=bogus_aggregator, ResourceIdentifiers=[identifier]
        )
    )
    assert code == "NoSuchConfigurationAggregatorException", f"expected NoSuchConfigurationAggregatorException, got {code!r}"
    assert code_message == (
        "The configuration aggregator does not exist. Check the configuration "
        "aggregator name and try again."
    ), code_message

    # Positive control: a real aggregator + the exact same never-discovered identifier succeeds.
    real_aggregator = ctx.unique_name("sim2real-realagg-")
    config.put_configuration_aggregator(
        ConfigurationAggregatorName=real_aggregator,
        AccountAggregationSources=[{"AccountIds": [account_id], "AwsRegions": [ctx.region]}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: config.delete_configuration_aggregator(ConfigurationAggregatorName=real_aggregator))

    resp = config.batch_get_aggregate_resource_config(
        ConfigurationAggregatorName=real_aggregator, ResourceIdentifiers=[identifier]
    )
    assert resp["BaseConfigurationItems"] == [], f"expected no BaseConfigurationItems for a never-discovered resource, got {resp['BaseConfigurationItems']!r}"
    unprocessed_ids = [u["ResourceId"] for u in resp["UnprocessedResourceIdentifiers"]]
    assert identifier["ResourceId"] in unprocessed_ids, (
        f"expected {identifier['ResourceId']!r} in UnprocessedResourceIdentifiers, got {unprocessed_ids!r}"
    )


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
