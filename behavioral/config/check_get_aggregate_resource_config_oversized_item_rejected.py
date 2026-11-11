"""get-aggregate-resource-config-oversized-item-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-aggregate-resource-config-oversized-item-rejected"
GROUP = "error-semantics"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAggregateResourceConfig on a live aggregator rejects a never-discovered resource with
    ResourceNotDiscoveredException at both an ordinary and the maximum 768-character ResourceId,
    and the same lookup on a missing aggregator fails NoSuchConfigurationAggregatorException.
    """
    config = ctx.client("config")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    agg_name = ctx.unique_name("sim2real-ossagg-")
    config.put_configuration_aggregator(
        ConfigurationAggregatorName=agg_name,
        AccountAggregationSources=[{"AccountIds": [account_id], "AwsRegions": [ctx.region]}],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: config.delete_configuration_aggregator(ConfigurationAggregatorName=agg_name))

    # Positive control: the aggregator itself is healthy and describes successfully (it does not
    # need a fully-synced source status to answer GetAggregateResourceConfig for a never-created
    # resource -- that answer is immediate, not dependent on a completed source sync).
    described = config.describe_configuration_aggregators(
        ConfigurationAggregatorNames=[agg_name]
    )["ConfigurationAggregators"]
    assert any(a["ConfigurationAggregatorName"] == agg_name for a in described), (
        f"expected {agg_name!r} among described aggregators, got "
        f"{[a['ConfigurationAggregatorName'] for a in described]}"
    )

    # Real, deterministic assertion #1: a never-discovered resource at an ordinary ResourceId
    # length resolves to the precise ResourceNotDiscoveredException.
    short_id_resource = {
        "SourceAccountId": account_id,
        "SourceRegion": ctx.region,
        "ResourceId": f"i-{uuid.uuid4().hex[:17]}",
        "ResourceType": "AWS::EC2::Instance",
    }
    code_short, message_short = _aggregate_error(config, agg_name, short_id_resource)
    assert code_short == "ResourceNotDiscoveredException", f"expected ResourceNotDiscoveredException, got {code_short}"
    assert message_short == _NOT_DISCOVERED, message_short

    # Real, deterministic assertion #2: the SAME never-discovered condition at the LONGEST valid
    # ResourceId (768 characters -- AggregateResourceIdentifier.ResourceId's own maximum) still
    # resolves to the same precise error rather than a different one (e.g. a spurious
    # ValidationException), proving boundary-length identifiers are not mis-handled.
    long_id_resource = dict(short_id_resource)
    long_id_resource["ResourceId"] = ("i-" + uuid.uuid4().hex).ljust(768, "0")[:768]
    assert len(long_id_resource["ResourceId"]) == 768, (
        f"expected the boundary ResourceId to be exactly 768 chars, got {len(long_id_resource['ResourceId'])}"
    )
    code_long, message_long = _aggregate_error(config, agg_name, long_id_resource)
    assert code_long == "ResourceNotDiscoveredException", f"expected ResourceNotDiscoveredException, got {code_long}"
    assert message_long == _NOT_DISCOVERED, message_long

    # Contrast: the same resource identifier against an aggregator that does not exist at all
    # yields a different, more specific error rather than the same one.
    bogus_agg = ctx.unique_name("sim2real-noagg-")
    code_no_agg, message_no_agg = _error(
        lambda: config.get_aggregate_resource_config(
            ConfigurationAggregatorName=bogus_agg, ResourceIdentifier=short_id_resource
        )
    )
    assert code_no_agg == "NoSuchConfigurationAggregatorException", (
        f"expected NoSuchConfigurationAggregatorException, got {code_no_agg}"
    )
    assert message_no_agg == _NO_SUCH_AGGREGATOR, message_no_agg


_NO_SUCH_AGGREGATOR = (
    "The configuration aggregator does not exist. Check the configuration aggregator name "
    "and try again."
)
_NOT_DISCOVERED = "You have specified a resource that is either unknown or has not been discovered."


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _aggregate_error(config, agg_name, resource_identifier):
    return _error(
        lambda: config.get_aggregate_resource_config(
            ConfigurationAggregatorName=agg_name, ResourceIdentifier=resource_identifier
        )
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
