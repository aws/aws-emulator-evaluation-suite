"""delete-rule-with-targets-requires-force."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-rule-with-targets-requires-force"
GROUP = 'rule'
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

def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")

def _rule_not_found(name: str, bus: str) -> str:
    return f"Rule {name} does not exist on EventBus {bus}."

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRule must refuse to drop a rule that still has targets, but must succeed on the
    identical call once those targets are removed — the restore leg is what tells "correctly
    rejects a rule with targets" apart from "rejects every DeleteRule call"."""
    ev = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_resp = ev.create_event_bus(Name=bus)
    ctx.on_cleanup(lambda n=bus: ev.delete_event_bus(Name=n))
    ev.tag_resource(ResourceARN=bus_resp["EventBusArn"], Tags=[{"Key": "sim2real", "Value": "behav"}])

    # ---- positive control: DeleteRule on a target-free rule succeeds on this same bus ----
    control_rule = ctx.unique_name("sim2real-behav-rule-control-")
    control_resp = ev.put_rule(Name=control_rule, EventBusName=bus, EventPattern='{"source": ["sim2real.behav"]}')
    ctx.on_cleanup(lambda n=control_rule, b=bus: _cleanup_rule(ev, n, b))
    ev.tag_resource(ResourceARN=control_resp["RuleArn"], Tags=[{"Key": "sim2real", "Value": "behav"}])
    ev.delete_rule(Name=control_rule, EventBusName=bus)
    control_err = _error(lambda: ev.describe_rule(Name=control_rule, EventBusName=bus))
    assert control_err == ("ResourceNotFoundException", _rule_not_found(control_rule, bus)), (
        f"positive control: DeleteRule on a target-free rule must succeed, but describe_rule "
        f"afterwards returned {control_err!r}"
    )

    # ---- break exactly one thing: attach a target to a second rule ----
    rule = ctx.unique_name("sim2real-behav-rule-")
    rule_resp = ev.put_rule(Name=rule, EventBusName=bus, EventPattern='{"source": ["sim2real.behav"]}')
    ctx.on_cleanup(lambda n=rule, b=bus: _cleanup_rule(ev, n, b))
    ev.tag_resource(ResourceARN=rule_resp["RuleArn"], Tags=[{"Key": "sim2real", "Value": "behav"}])
    ev.put_targets(
        Rule=rule,
        EventBusName=bus,
        Targets=[{"Id": "t1", "Arn": _lambda_target_arn(rule_resp["RuleArn"])}],
    )
    err = _error(lambda: ev.delete_rule(Name=rule, EventBusName=bus))
    assert err == ("ValidationException", "Rule can't be deleted since it has targets."), (
        f"expected DeleteRule with attached targets to fail with ValidationException, got {err!r}"
    )
    desc = ev.describe_rule(Name=rule, EventBusName=bus)
    assert desc["Name"] == rule, "rule must survive a rejected DeleteRule"

    # ---- restore: remove the target, then the identical DeleteRule call now succeeds ----
    ev.remove_targets(Rule=rule, EventBusName=bus, Ids=["t1"])
    try:
        ev.delete_rule(Name=rule, EventBusName=bus)
        restored_code = None
    except ClientError as exc:
        restored_code = exc.response.get("Error", {}).get("Code")
    assert restored_code is None, (
        f"expected DeleteRule to succeed once the rule has no targets, got {restored_code}"
    )
    after_err = _error(lambda: ev.describe_rule(Name=rule, EventBusName=bus))
    assert after_err == ("ResourceNotFoundException", _rule_not_found(rule, bus)), (
        f"expected the rule to be gone after the restored DeleteRule, describe_rule returned {after_err!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
