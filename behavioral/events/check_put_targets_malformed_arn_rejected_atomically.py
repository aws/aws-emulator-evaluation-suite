"""put-targets-malformed-arn-rejected-atomically."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-targets-malformed-arn-rejected-atomically"
GROUP = 'targets'
SERVICES = ['events']


def _client_error(fn):
    """Call fn() and return the botocore Error dict it raised; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _cleanup_rule(ev, name):
    """Remove any attached targets, then delete the rule (DeleteRule refuses a rule with targets)."""
    try:
        targets = ev.list_targets_by_rule(Rule=name).get("Targets", [])
        if targets:
            ev.remove_targets(Rule=name, Ids=[t["Id"] for t in targets])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    ev.delete_rule(Name=name, Force=True)


def _synthetic_queue_arn(ev, ctx):
    """A syntactically valid SQS queue ARN in this account/region.

    EventBridge accepts target ARNs without requiring the target resource to exist.
    """
    bus_arn = ev.describe_event_bus(Name="default")["Arn"]
    parts = bus_arn.split(":")
    partition, region, account = parts[1], parts[3], parts[4]
    return (
        f"arn:{partition}:sqs:{region}:{account}:"
        + ctx.unique_name("sim2real-behav-evb-target-")
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A malformed target ARN fails the whole PutTargets call with ValidationException rather than
    a per-target FailedEntry, and the well-formed sibling target in the same batch is not added."""
    ev = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-behav-evb-rule-")
    ev.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": ["x"]}),
        Tags=[{"Key": "sim2real-behav", "Value": "check_put_targets_malformed_arn_rejected_atomically"}],
    )
    ctx.on_cleanup(lambda: _cleanup_rule(ev, rule_name))

    target_arn = _synthetic_queue_arn(ev, ctx)

    err = _client_error(
        lambda: ev.put_targets(
            Rule=rule_name,
            Targets=[
                {"Id": "good-target", "Arn": target_arn},
                {"Id": "bad-target", "Arn": "not-a-valid-arn"},
            ],
        )
    )
    assert err.get("Code") == "ValidationException", f"expected ValidationException, got {err}"
    expected_message = "Parameter not-a-valid-arn is not valid. Reason: Provided Arn is not in correct format."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    targets = ev.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert targets == [], (
        f"a rejected PutTargets must not partially apply, but found {targets}"
    )

    # The same batch minus the malformed ARN succeeds, proving the rejection was
    # caused by the ARN and not by the batch shape.
    ok = ev.put_targets(
        Rule=rule_name, Targets=[{"Id": "good-target", "Arn": target_arn}]
    )
    assert ok["FailedEntryCount"] == 0, f"well-formed target should be accepted: {ok}"
    ids = {t["Id"] for t in ev.list_targets_by_rule(Rule=rule_name)["Targets"]}
    assert ids == {"good-target"}, f"expected only 'good-target' attached, got {ids}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
