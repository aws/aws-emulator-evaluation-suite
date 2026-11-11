"""get-aggregate-resource-config-not-discovered-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-aggregate-resource-config-not-discovered-rejected"
GROUP = "error-semantics"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAggregateResourceConfig for a resource identifier that the aggregator source has never
    discovered raises ResourceNotDiscoveredException, distinct from NoSuchConfigurationAggregatorException
    when the aggregator itself does not exist."""
    config = ctx.client("config")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    agg_name = ctx.unique_name("sim2real-agg-")
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

    fake_resource = {
        "SourceAccountId": account_id,
        "SourceRegion": ctx.region,
        "ResourceId": f"i-{uuid.uuid4().hex[:17]}",
        "ResourceType": "AWS::EC2::Instance",
    }

    code, message = _error(
        lambda: config.get_aggregate_resource_config(
            ConfigurationAggregatorName=agg_name, ResourceIdentifier=fake_resource
        )
    )
    assert code == "ResourceNotDiscoveredException", f"expected ResourceNotDiscoveredException, got {code}"
    assert message == _NOT_DISCOVERED, message

    # Contrast: the same resource identifier against an aggregator name that does not exist at
    # all yields a different, more specific error rather than the same one.
    bogus_agg = ctx.unique_name("sim2real-noagg-")
    code2, message2 = _error(
        lambda: config.get_aggregate_resource_config(
            ConfigurationAggregatorName=bogus_agg, ResourceIdentifier=fake_resource
        )
    )
    assert code2 == "NoSuchConfigurationAggregatorException", f"expected NoSuchConfigurationAggregatorException, got {code2}"
    assert message2 == _NO_SUCH_AGGREGATOR, message2


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
