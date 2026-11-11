"""overly-permissive-aggregator-invalid-account-id."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_aggregator_quiet(cfg, name):
    try:
        cfg.delete_configuration_aggregator(ConfigurationAggregatorName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchConfigurationAggregatorException":
            raise


CHECK = "overly-permissive-aggregator-invalid-account-id"
GROUP = "overly-permissive"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutConfigurationAggregator with a source account id that is not 12 digits fails with
    ValidationException and its exact message and the aggregator does not exist after, while a
    well-formed aggregator is created."""
    cfg = ctx.client("config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    valid_name = ctx.unique_name("sim2real-behav-cfg-agg-valid-")
    cfg.put_configuration_aggregator(
        ConfigurationAggregatorName=valid_name,
        AccountAggregationSources=[{"AccountIds": [account_id], "AllAwsRegions": True}],
    )
    ctx.on_cleanup(
        lambda a=valid_name: cfg.delete_configuration_aggregator(ConfigurationAggregatorName=a)
    )
    described = cfg.describe_configuration_aggregators(ConfigurationAggregatorNames=[valid_name])[
        "ConfigurationAggregators"
    ]
    assert len(described) == 1, described

    agg_name = ctx.unique_name("sim2real-behav-cfg-agg-")
    ctx.on_cleanup(lambda a=agg_name: _delete_aggregator_quiet(cfg, a))

    code, message = _error(
        lambda: cfg.put_configuration_aggregator(
            ConfigurationAggregatorName=agg_name,
            AccountAggregationSources=[{"AccountIds": ["12345"], "AllAwsRegions": True}],
        )
    )
    assert code == "ValidationException", code
    assert message == (
        "1 validation error detected: Value '[12345]' at "
        "'accountAggregationSources.1.member.accountIds' failed to satisfy constraint: "
        "Member must satisfy constraint: [Member must have length less than or equal to 12, "
        "Member must have length greater than or equal to 12, "
        "Member must satisfy regular expression pattern: \\d{12}]"
    ), message

    missing, message = _error(
        lambda: cfg.describe_configuration_aggregators(ConfigurationAggregatorNames=[agg_name])
    )
    assert missing == "NoSuchConfigurationAggregatorException", missing
    assert message == (
        "The configuration aggregator does not exist. Check the configuration aggregator name "
        "and try again."
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
