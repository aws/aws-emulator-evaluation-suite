"""select-aggregate-resource-config-errors."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

CHECK = "select-aggregate-resource-config-errors"
GROUP = 'aggregator'
SERVICES = ['config']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SelectAggregateResourceConfig must reject an unknown aggregator and a
    malformed expression with distinct, specific error codes, while a well-formed
    query against a real aggregator keeps succeeding around both rejections."""
    cfg = ctx.client("config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    code, message = _error(
        lambda: cfg.select_aggregate_resource_config(
            Expression="SELECT resourceId",
            ConfigurationAggregatorName=ctx.unique_name("sim2real-behav-cfg-absent-agg-"),
        )
    )
    assert code == "NoSuchConfigurationAggregatorException", code
    assert message == (
        "The configuration aggregator does not exist. "
        "Check the configuration aggregator name and try again."
    ), message

    name = ctx.unique_name("sim2real-behav-cfg-aggregator-")
    cfg.put_configuration_aggregator(
        ConfigurationAggregatorName=name,
        AccountAggregationSources=[
            {"AccountIds": [account_id], "AwsRegions": [ctx.region]}
        ],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda a=name: cfg.delete_configuration_aggregator(ConfigurationAggregatorName=a))

    # Positive control: the same operation, on the aggregator that now exists, with a
    # well-formed expression, must succeed -- otherwise the two rejections below are
    # indistinguishable from "every call to this operation fails".
    control = cfg.select_aggregate_resource_config(
        Expression="SELECT resourceId", ConfigurationAggregatorName=name
    )
    assert isinstance(control["Results"], list), control

    code, message = _error(
        lambda: cfg.select_aggregate_resource_config(
            Expression="SELECT ((( invalid", ConfigurationAggregatorName=name
        )
    )
    assert code == "InvalidExpressionException", code
    assert message == "syntax error at line 1, column 19", message

    # Control still works: the rejection must not have wedged the query surface.
    again = cfg.select_aggregate_resource_config(
        Expression="SELECT resourceId", ConfigurationAggregatorName=name
    )
    assert isinstance(again["Results"], list), again


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
