"""aggregator-source-exclusivity-rejected."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


CHECK = "aggregator-source-exclusivity-rejected"
GROUP = 'aggregator'
SERVICES = ['config']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "identity:standalone", "phase:standalone", "plane:control")
def run(ctx) -> None:
    """PutConfigurationAggregator fails with InvalidParameterValueException and exact messages for
    AllAwsRegions together with AwsRegions, for neither, and for account plus organization sources, and
    creates none of those, while a single well-formed account source is stored as sent and listed once."""
    cfg = ctx.client("config")
    account = ctx.account

    # Control first: one well-formed account source is accepted and echoed exactly.
    control = ctx.unique_name("sim2real-behav-cfg-aggregator-")
    created = cfg.put_configuration_aggregator(
        ConfigurationAggregatorName=control,
        AccountAggregationSources=[
            {"AccountIds": [account], "AwsRegions": [ctx.region], "AllAwsRegions": False}
        ],
        Tags=[{"Key": "owner", "Value": "fidelity"}],
    )["ConfigurationAggregator"]
    ctx.on_cleanup(
        lambda n=control: cfg.delete_configuration_aggregator(
            ConfigurationAggregatorName=n
        )
    )
    assert created["ConfigurationAggregatorName"] == control, (
        "ConfigurationAggregatorName is not echoed as submitted"
    )
    sources = created["AccountAggregationSources"]
    assert len(sources) == 1, f"expected 1 AccountAggregationSource, got {len(sources)}"
    assert sources[0]["AccountIds"] == [account], "AccountIds is not echoed as submitted"
    assert sources[0]["AwsRegions"] == [ctx.region], "AwsRegions is not echoed as submitted"
    assert sources[0]["AllAwsRegions"] is False, (
        f"AllAwsRegions must be echoed as the submitted False, not defaulted or "
        f"dropped, got {sources[0].get('AllAwsRegions')!r}"
    )
    assert "OrganizationAggregationSource" not in created, (
        "OrganizationAggregationSource is present on an account-source aggregator"
    )

    # The third element is the exact refusal message real AWS returns. It does not
    # name the offending request field for the two region legs -- it returns prose
    # describing the conflict; only the source-exclusivity leg names
    # AccountAggregationSource/OrganizationAggregationSource. All three legs share
    # InvalidParameterValueException, so the message is the only thing that tells
    # them apart.
    legs = [
        (
            "AllAwsRegions=True together with an explicit AwsRegions list",
            {
                "AccountAggregationSources": [
                    {
                        "AccountIds": [account],
                        "AwsRegions": [ctx.region],
                        "AllAwsRegions": True,
                    }
                ]
            },
            "Your configuration aggregator contains a list of regions and also specifies "
            "the use of all regions. You must choose one of these options.",
        ),
        (
            "neither AllAwsRegions nor AwsRegions",
            {"AccountAggregationSources": [{"AccountIds": [account]}]},
            "Your request does not specify any regions. Select AWS Config-supported regions "
            "and try again.",
        ),
        (
            "an account source together with an organization source",
            {
                "AccountAggregationSources": [
                    {"AccountIds": [account], "AwsRegions": [ctx.region]}
                ],
                "OrganizationAggregationSource": {
                    "RoleArn": f"arn:aws:iam::{account}:role/sim2real-behav-cfg-org-agg",
                    "AwsRegions": [ctx.region],
                },
            },
            "The configuration aggregator cannot be created because your request contains "
            "both the AccountAggregationSource and the OrganizationAggregationSource. Include "
            "only one aggregation source and try again.",
        ),
    ]
    for description, body, expected_message in legs:
        name = ctx.unique_name("sim2real-behav-cfg-aggregator-bad-")
        code, message = _error(
            lambda b=body, n=name: cfg.put_configuration_aggregator(
                ConfigurationAggregatorName=n, **b
            )
        )
        assert code == "InvalidParameterValueException", (
            f"{description} must be refused with InvalidParameterValueException; "
            f"got {code!r} (message {message!r})"
        )
        assert message == expected_message, (
            f"{description}: the refusal must read {expected_message!r} -- the three "
            f"legs share one error code, so the message is the only thing that "
            f"tells them apart; got {message!r}"
        )
        # Effect absent: the aggregator name must not resolve.
        missing, missing_message = _error(
            lambda n=name: cfg.describe_configuration_aggregators(
                ConfigurationAggregatorNames=[n]
            )
        )
        assert missing == "NoSuchConfigurationAggregatorException", (
            f"{description} was refused but its aggregator exists (got {missing!r})"
        )
        assert missing_message == (
            "The configuration aggregator does not exist. Check the configuration "
            "aggregator name and try again."
        ), missing_message

    # Control still works and is byte-identical after three refusals.
    after = cfg.describe_configuration_aggregators(
        ConfigurationAggregatorNames=[control]
    )["ConfigurationAggregators"]
    assert len(after) == 1, f"expected the control aggregator once, got {len(after)}"
    assert after[0]["AccountAggregationSources"][0]["AwsRegions"] == [ctx.region], (
        "the control aggregator's AwsRegions changed after the refusals"
    )
    assert after[0]["AccountAggregationSources"][0]["AllAwsRegions"] is False, (
        "the control aggregator's AllAwsRegions changed after the refusals"
    )
    assert "OrganizationAggregationSource" not in after[0], (
        "a refused OrganizationAggregationSource must not have leaked onto the "
        "control aggregator"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
