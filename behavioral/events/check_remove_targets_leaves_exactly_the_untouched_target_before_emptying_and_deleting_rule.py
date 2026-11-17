"""remove-targets-leaves-exactly-the-untouched-target-before-emptying-and-deleting-rule."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "remove-targets-leaves-exactly-the-untouched-target-before-emptying-and-deleting-rule"
GROUP = 'targets'
SERVICES = ['events']


def _sqs_target_arn(ref_arn: str) -> str:
    """Syntactic SQS target ARN in ref_arn's partition/region/account (EventBridge does not verify existence)."""
    p = ref_arn.split(":")
    return f"arn:{p[1]}:sqs:{p[3]}:{p[4]}:sim2real-behav-q-{uuid.uuid4().hex[:8]}"


def _cleanup_rule(client, name, bus):
    """Remove any attached targets, then delete the rule (delete_rule refuses a rule with targets)."""
    try:
        ids = [t["Id"] for t in client.list_targets_by_rule(Rule=name, EventBusName=bus).get("Targets", [])]
        if ids:
            client.remove_targets(Rule=name, Ids=ids, EventBusName=bus)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
    client.delete_rule(Name=name, EventBusName=bus, Force=True)


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveTargets on two of three Ids leaves exactly the untouched target; removing the
    last one empties the rule, letting DeleteRule succeed and DescribeRule 404 on it.
    """
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=bus)
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))
    rule = ctx.unique_name("sim2real-behav-rule-")
    rule_resp = ev.put_rule(Name=rule, EventBusName=bus, EventPattern='{"source": ["sim2real.behav"]}')
    ctx.on_cleanup(lambda n=rule, b=bus: _cleanup_rule(ev, n, b))

    arn_t1 = _sqs_target_arn(rule_resp["RuleArn"])
    arn_t2 = _sqs_target_arn(rule_resp["RuleArn"])
    arn_t3 = _sqs_target_arn(rule_resp["RuleArn"])
    put_resp = ev.put_targets(
        Rule=rule,
        EventBusName=bus,
        Targets=[
            {"Id": "t1", "Arn": arn_t1},
            {"Id": "t2", "Arn": arn_t2},
            {"Id": "t3", "Arn": arn_t3},
        ],
    )
    assert put_resp.get("FailedEntryCount", 0) == 0, f"PutTargets unexpectedly failed: {put_resp}"
    before = ev.list_targets_by_rule(Rule=rule, EventBusName=bus).get("Targets", [])
    before_ids = sorted(t["Id"] for t in before)
    assert before_ids == ["t1", "t2", "t3"], f"expected all three targets attached, got {before_ids}"

    partial = ev.remove_targets(Rule=rule, EventBusName=bus, Ids=["t1", "t3"])
    assert partial.get("FailedEntryCount", 0) == 0, f"partial RemoveTargets unexpectedly failed: {partial}"
    after_partial = ev.list_targets_by_rule(Rule=rule, EventBusName=bus).get("Targets", [])
    assert after_partial == [{"Id": "t2", "Arn": arn_t2}], (
        f"expected exactly the untouched target t2 to remain after removing t1 and t3, got {after_partial!r}"
    )

    full = ev.remove_targets(Rule=rule, EventBusName=bus, Ids=["t2"])
    assert full.get("FailedEntryCount", 0) == 0, f"final RemoveTargets unexpectedly failed: {full}"
    after_full = ev.list_targets_by_rule(Rule=rule, EventBusName=bus).get("Targets", [])
    assert after_full == [], f"rule must have no targets after removing the last one, got {after_full!r}"

    ev.delete_rule(Name=rule, EventBusName=bus)
    expected = ("ResourceNotFoundException", f"Rule {rule} does not exist on EventBus {bus}.")
    err = _error(lambda: ev.describe_rule(Name=rule, EventBusName=bus))
    assert err == expected, f"expected {expected} from DescribeRule on a deleted rule, got {err}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
