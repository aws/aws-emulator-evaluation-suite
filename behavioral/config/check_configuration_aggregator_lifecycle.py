"""configuration-aggregator-lifecycle."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


CHECK = "configuration-aggregator-lifecycle"
GROUP = 'aggregator'
SERVICES = ['config']

_NO_SUCH_AGGREGATOR_MESSAGE = (
    "The configuration aggregator does not exist. Check the configuration aggregator name "
    "and try again."
)

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutConfigurationAggregator creates an account aggregator whose fields read back from
    DescribeConfigurationAggregators; after DeleteConfigurationAggregator, describe and a second delete
    fail with NoSuchConfigurationAggregatorException and its exact message, and the name is reusable."""
    cfg = ctx.client("config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-cfg-aggregator-")
    tag_spec = [{"Key": "sim2real:behavioral-check", "Value": CHECK}]
    cfg.put_configuration_aggregator(
        ConfigurationAggregatorName=name,
        AccountAggregationSources=[
            {"AccountIds": [account_id], "AllAwsRegions": True}
        ],
        Tags=tag_spec,
    )
    ctx.on_cleanup(lambda a=name: cfg.delete_configuration_aggregator(ConfigurationAggregatorName=a))

    described = cfg.describe_configuration_aggregators(
        ConfigurationAggregatorNames=[name]
    )["ConfigurationAggregators"]
    assert len(described) == 1, described
    assert described[0]["ConfigurationAggregatorName"] == name, described[0]
    sources = described[0]["AccountAggregationSources"]
    assert sources[0]["AccountIds"] == [account_id], sources
    assert sources[0]["AllAwsRegions"] is True, sources

    cfg.delete_configuration_aggregator(ConfigurationAggregatorName=name)
    code, code_message = _error(
        lambda: cfg.describe_configuration_aggregators(
            ConfigurationAggregatorNames=[name]
        )
    )
    assert code == "NoSuchConfigurationAggregatorException", code
    assert code_message == _NO_SUCH_AGGREGATOR_MESSAGE, code_message

    # A mutation against the deleted aggregator fails too, not just a read.
    code, code_message = _error(
        lambda: cfg.delete_configuration_aggregator(ConfigurationAggregatorName=name)
    )
    assert code == "NoSuchConfigurationAggregatorException", code
    assert code_message == _NO_SUCH_AGGREGATOR_MESSAGE, code_message

    # The freed name is reusable: recreate under the same name and prove it
    # round-trips again through an independent read; cleanup deletes it.
    cfg.put_configuration_aggregator(
        ConfigurationAggregatorName=name,
        AccountAggregationSources=[
            {"AccountIds": [account_id], "AllAwsRegions": True}
        ],
        Tags=tag_spec,
    )
    recreated = cfg.describe_configuration_aggregators(
        ConfigurationAggregatorNames=[name]
    )["ConfigurationAggregators"]
    assert len(recreated) == 1, recreated
    assert recreated[0]["ConfigurationAggregatorName"] == name, recreated[0]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
