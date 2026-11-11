"""remove-targets-removes-them."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "remove-targets-removes-them"
GROUP = 'targets'
SERVICES = ['events']

def _lambda_target_arn(ref_arn: str) -> str:
    """Syntactic Lambda target ARN in ref_arn's partition/region/account (EventBridge does not verify existence)."""
    p = ref_arn.split(":")
    return f"arn:{p[1]}:lambda:{p[3]}:{p[4]}:function:sim2real-behav-fn-{uuid.uuid4().hex[:8]}"

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

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveTargets detaches a target so it no longer appears in ListTargetsByRule."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=bus)
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))
    rule = ctx.unique_name("sim2real-behav-rule-")
    rule_resp = ev.put_rule(Name=rule, EventBusName=bus, EventPattern='{"source": ["sim2real.behav"]}')
    ctx.on_cleanup(lambda n=rule, b=bus: _cleanup_rule(ev, n, b))
    target_arn = _lambda_target_arn(rule_resp["RuleArn"])
    ev.put_targets(Rule=rule, EventBusName=bus, Targets=[{"Id": "t1", "Arn": target_arn}])
    before = ev.list_targets_by_rule(Rule=rule, EventBusName=bus)
    ids_before = [t["Id"] for t in before.get("Targets", [])]
    assert "t1" in ids_before, f"put_targets should have attached t1 before removal: {before}"
    resp = ev.remove_targets(Rule=rule, EventBusName=bus, Ids=["t1"])
    assert resp.get("FailedEntryCount", 0) == 0, f"remove_targets unexpectedly failed: {resp}"
    listed = ev.list_targets_by_rule(Rule=rule, EventBusName=bus)
    ids = [t["Id"] for t in listed.get("Targets", [])]
    assert "t1" not in ids, f"t1 should have been detached by remove_targets, got {ids}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
