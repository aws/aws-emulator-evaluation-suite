"""put-targets-exceeds-max-limit."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-targets-exceeds-max-limit"
GROUP = 'targets'
SERVICES = ['events']


def _client_error(fn):
    """Botocore Error dict of a call that must fail; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected the over-limit PutTargets call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


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
    """A valid SQS queue ARN in this account/region; EventBridge does not require the target
    to exist, so no queue is created."""
    bus_arn = ev.describe_event_bus(Name="default")["Arn"]
    parts = bus_arn.split(":")
    partition, region, account = parts[1], parts[3], parts[4]
    return (
        f"arn:{partition}:sqs:{region}:{account}:"
        + ctx.unique_name("sim2real-behav-evb-target-")
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutTargets with 6 targets, over the fixed 5-per-rule quota, fails with LimitExceededException
    and adds none, while the same batch minus one target is accepted."""
    ev = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-behav-evb-rule-")
    ev.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": ["x"]}),
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _cleanup_rule(ev, rule_name))

    target_arn = _synthetic_queue_arn(ev, ctx)
    over_limit = [{"Id": f"t-{i}", "Arn": target_arn} for i in range(6)]

    err = _client_error(lambda: ev.put_targets(Rule=rule_name, Targets=over_limit))
    assert err.get("Code") == "LimitExceededException", f"expected LimitExceededException, got {err}"
    expected_message = "The requested resource exceeds the maximum number allowed."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    remaining = ev.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert remaining == [], f"rejected PutTargets call must not add any targets: {remaining}"

    at_max = over_limit[:5]
    ok = ev.put_targets(Rule=rule_name, Targets=at_max)
    assert ok["FailedEntryCount"] == 0, f"a within-limit PutTargets should be accepted: {ok}"
    listed = {t["Id"] for t in ev.list_targets_by_rule(Rule=rule_name)["Targets"]}
    assert listed == {t["Id"] for t in at_max}, f"expected {[t['Id'] for t in at_max]} visible, got {listed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
