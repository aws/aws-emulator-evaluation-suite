"""aggregator-update-and-tagging."""

from __future__ import annotations

from behavioral_harness import tags


CHECK = "aggregator-update-and-tagging"
GROUP = 'aggregator'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutConfigurationAggregator updates an existing aggregator in place (same
    ARN, replaced sources) rather than creating a duplicate, and the resulting
    ARN supports the tag/untag round-trip."""
    cfg = ctx.client("config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-cfg-aggregator-")
    cfg.put_configuration_aggregator(
        ConfigurationAggregatorName=name,
        AccountAggregationSources=[
            {"AccountIds": [account_id], "AllAwsRegions": True}
        ],
    )
    ctx.on_cleanup(lambda a=name: cfg.delete_configuration_aggregator(ConfigurationAggregatorName=a))

    first = cfg.describe_configuration_aggregators(
        ConfigurationAggregatorNames=[name]
    )["ConfigurationAggregators"][0]
    arn = first["ConfigurationAggregatorArn"]
    assert first["AccountAggregationSources"][0]["AllAwsRegions"] is True, first

    # Update in place: switch from AllAwsRegions to an explicit region list.
    cfg.put_configuration_aggregator(
        ConfigurationAggregatorName=name,
        AccountAggregationSources=[
            {"AccountIds": [account_id], "AwsRegions": [ctx.region]}
        ],
    )
    described = cfg.describe_configuration_aggregators(
        ConfigurationAggregatorNames=[name]
    )["ConfigurationAggregators"]
    assert len(described) == 1, described
    assert described[0]["ConfigurationAggregatorArn"] == arn, described[0]
    source = described[0]["AccountAggregationSources"][0]
    assert source.get("AwsRegions") == [ctx.region], source
    assert not source.get("AllAwsRegions"), source

    cfg.tag_resource(
        ResourceArn=arn,
        Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
    )
    tags = {
        t["Key"]: t["Value"]
        for t in cfg.list_tags_for_resource(ResourceArn=arn)["Tags"]
    }
    assert tags.get("env") == "test" and tags.get("owner") == "fidelity", tags

    cfg.untag_resource(ResourceArn=arn, TagKeys=["owner"])
    tags = {
        t["Key"]: t["Value"]
        for t in cfg.list_tags_for_resource(ResourceArn=arn)["Tags"]
    }
    assert "owner" not in tags and tags.get("env") == "test", tags


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
