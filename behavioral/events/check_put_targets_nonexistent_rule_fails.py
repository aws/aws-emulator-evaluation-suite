"""put-targets-nonexistent-rule-fails."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-targets-nonexistent-rule-fails"
GROUP = 'targets'
SERVICES = ['events']

def _lambda_target_arn(ref_arn: str) -> str:
    """Syntactic Lambda target ARN in ref_arn's partition/region/account (EventBridge does not verify existence)."""
    p = ref_arn.split(":")
    return f"arn:{p[1]}:lambda:{p[3]}:{p[4]}:function:sim2real-behav-fn-{uuid.uuid4().hex[:8]}"

def _cleanup_rule(ev, name: str, bus: str) -> None:
    """Teardown: DeleteRule refuses a rule that still has targets, so remove them first."""
    ids = [t["Id"] for t in ev.list_targets_by_rule(Rule=name, EventBusName=bus).get("Targets", [])]
    if ids:
        ev.remove_targets(Rule=name, EventBusName=bus, Ids=ids, Force=True)
    ev.delete_rule(Name=name, EventBusName=bus, Force=True)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """OVERLY-PERMISSIVE: PutTargets against a nonexistent rule must fail, must not
    register a residual target that later appears once a same-named rule is created,
    and the identical call must succeed once that rule genuinely exists."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_resp = ev.create_event_bus(Name=bus, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))
    rule = ctx.unique_name("sim2real-behav-rule-")
    target_arn = _lambda_target_arn(bus_resp["EventBusArn"])

    # Positive control: PutTargets against a real rule on the same bus succeeds,
    # so a rejection below cannot be indistinguishable from "rejects every PutTargets".
    control_rule = ctx.unique_name("sim2real-behav-rule-ctl-")
    ev.put_rule(
        Name=control_rule, EventBusName=bus,
        EventPattern='{"source": ["sim2real.control"]}',
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=control_rule, b=bus: _cleanup_rule(ev, n, b))
    ev.put_targets(Rule=control_rule, EventBusName=bus, Targets=[{'Id': 'ctl', 'Arn': target_arn}])
    control_targets = ev.list_targets_by_rule(Rule=control_rule, EventBusName=bus)["Targets"]
    assert len(control_targets) == 1, f"expected positive control to register 1 target, got {control_targets}"

    # Break: `rule` has never been created — PutTargets against it must fail.
    try:
        result = ev.put_targets(Rule=rule, EventBusName=bus, Targets=[{'Id': 't1', 'Arn': target_arn}])
    except ClientError as exc:
        err = exc.response.get("Error", {})
    else:
        raise AssertionError(f"PutTargets against a nonexistent rule SUCCEEDED: {result!r}")
    assert err.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {err}"
    expected_message = f"Rule {rule} does not exist on EventBus {bus}."
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    # Restore: create the identically-named rule, and prove the earlier rejected call
    # left no residual target queued for it — an independent read at the destination.
    ev.put_rule(
        Name=rule, EventBusName=bus,
        EventPattern='{"source": ["sim2real.restored"]}',
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda n=rule, b=bus: _cleanup_rule(ev, n, b))
    residual = ev.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"]
    assert residual == [], f"expected no residual target on newly-created rule, got {residual}"

    # The identical call now succeeds against the restored rule.
    ev.put_targets(Rule=rule, EventBusName=bus, Targets=[{'Id': 't1', 'Arn': target_arn}])
    restored_targets = ev.list_targets_by_rule(Rule=rule, EventBusName=bus)["Targets"]
    assert [t["Id"] for t in restored_targets] == ["t1"], (
        f"expected target t1 registered after restore, got {restored_targets}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
