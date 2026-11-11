"""remove-targets-unknown-id-is-lenient."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "remove-targets-unknown-id-is-lenient"
GROUP = 'targets'
SERVICES = ['events']


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveTargets silently ignores unknown target Ids (FailedEntryCount 0, no FailedEntries) and
    still removes the known Id in the same call; repeating the removal is idempotent."""
    ev = ctx.client("events")
    rule_name = ctx.unique_name("sim2real-behav-evb-rule-")
    ev.put_rule(
        Name=rule_name,
        EventPattern=json.dumps({"source": ["x"]}),
        Tags=[{"Key": "sim2real", "Value": "events-behavioral"}],
    )
    ctx.on_cleanup(lambda: _cleanup_rule(ev, rule_name))

    target_arn = _synthetic_queue_arn(ev, ctx)
    ev.put_targets(Rule=rule_name, Targets=[{"Id": "kept", "Arn": target_arn}])

    resp = ev.remove_targets(Rule=rule_name, Ids=["kept", "never-existed"])
    assert resp["FailedEntryCount"] == 0, f"unknown Id must not be reported as failed: {resp}"
    assert resp.get("FailedEntries", []) == [], f"expected no FailedEntries, got {resp}"

    remaining = ev.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert remaining == [], f"the existing 'kept' target should have been removed: {remaining}"

    again = ev.remove_targets(Rule=rule_name, Ids=["kept"])
    assert again["FailedEntryCount"] == 0, f"repeat removal must be idempotent: {again}"

    still_remaining = ev.list_targets_by_rule(Rule=rule_name)["Targets"]
    assert still_remaining == [], f"repeat removal must not resurrect or alter targets: {still_remaining}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
