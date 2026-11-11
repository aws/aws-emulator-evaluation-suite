"""op-delete-aggregator-nonexistent-and-bad-name."""

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


_NO_SUCH_AGGREGATOR = (
    "The configuration aggregator does not exist. Check the configuration aggregator name "
    "and try again."
)

CHECK = "op-delete-aggregator-nonexistent-and-bad-name"
GROUP = 'overly-permissive'
SERVICES = ['config']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteConfigurationAggregator on an unknown aggregator fails with
    NoSuchConfigurationAggregatorException and its exact message, as does a second delete of a real one,
    and a name outside [\\w\\-]+ fails with ValidationException and is never stored."""
    cfg = ctx.client("config")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    missing = ctx.unique_name("sim2real-behav-cfg-absent-agg-")
    code, message = _error(
        lambda: cfg.delete_configuration_aggregator(
            ConfigurationAggregatorName=missing
        )
    )
    assert code == "NoSuchConfigurationAggregatorException", code
    assert message == _NO_SUCH_AGGREGATOR, message

    # Positive control: a real aggregator can be created, read back and
    # deleted -- the rejection above is specific to the missing name, not
    # every delete call.
    real_name = ctx.unique_name("sim2real-behav-cfg-real-agg-")
    cfg.put_configuration_aggregator(
        ConfigurationAggregatorName=real_name,
        AccountAggregationSources=[
            {"AccountIds": [account_id], "AllAwsRegions": True}
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_aggregator_quiet(cfg, real_name))
    described = cfg.describe_configuration_aggregators(
        ConfigurationAggregatorNames=[real_name]
    )["ConfigurationAggregators"]
    assert (
        len(described) == 1
        and described[0]["ConfigurationAggregatorName"] == real_name
    ), described

    cfg.delete_configuration_aggregator(ConfigurationAggregatorName=real_name)
    gone, message = _error(
        lambda: cfg.describe_configuration_aggregators(
            ConfigurationAggregatorNames=[real_name]
        )
    )
    assert gone == "NoSuchConfigurationAggregatorException", gone
    assert message == _NO_SUCH_AGGREGATOR, message

    # Name pattern is enforced server-side (botocore only checks length).
    bad_name = "bad name with spaces!"
    code, message = _error(
        lambda: cfg.put_configuration_aggregator(
            ConfigurationAggregatorName=bad_name,
            AccountAggregationSources=[
                {"AccountIds": [account_id], "AllAwsRegions": True}
            ],
        )
    )
    assert code == "ValidationException", code
    assert message == (
        f"1 validation error detected: Value '{bad_name}' at 'configurationAggregatorName' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w\\-]+"
    ), message

    # Effect-absent: the rejected name must not have been stored despite the
    # error. The valid put above already proves the rejection is specific to
    # the malformed name, not every put.
    all_names = {
        a["ConfigurationAggregatorName"]
        for a in cfg.describe_configuration_aggregators()["ConfigurationAggregators"]
    }
    assert bad_name not in all_names, all_names


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
