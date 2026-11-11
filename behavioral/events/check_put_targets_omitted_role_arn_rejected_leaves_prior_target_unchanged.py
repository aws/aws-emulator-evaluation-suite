"""put-targets-omitted-role-arn-rejected-leaves-prior-target-unchanged."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# Real AWS rejects a role-requiring target without RoleArn outright (never a silent null or a
# merge with the stored role). A cross-account bus target needs a second account, so a Step
# Functions target proves the same RoleArn-is-mandatory-and-atomic invariant.

CHECK = "put-targets-omitted-role-arn-rejected-leaves-prior-target-unchanged"
GROUP = "targets"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutTargets omitting RoleArn for a role-requiring target is refused on create and on both
    update shapes, leaving the stored target unchanged; the rule's RoleArn is never inherited.
    """
    events = ctx.client("events")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    rule_role_arn = _create_events_role(ctx, iam, ctx.unique_name("sim2real-behav-rulerole-"))
    target_role_arn = _create_events_role(ctx, iam, ctx.unique_name("sim2real-behav-targetrole-"))

    rule_name = ctx.unique_name("sim2real-behav-rule-")
    pattern = json.dumps({"source": [ctx.unique_name("sim2real.rolearn.")]})
    _put_rule_with_retry(ctx, events, rule_name, pattern, rule_role_arn)
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))
    ctx.on_cleanup(lambda: _remove_targets_quietly(events, rule_name))

    sm_arn = f"arn:aws:states:{ctx.region}:{account}:stateMachine:{ctx.unique_name('sim2real-behav-sm-')}"

    # 1. The very first PutTargets for this Id, with RoleArn omitted, must be refused -- not
    # accepted with a null role, and NOT silently inheriting the rule's own RoleArn.
    kind, code, msg = _attempt_put_targets(events, rule_name, {"Id": "t1", "Arn": sm_arn})
    assert kind == "exception", f"expected a whole-request rejection, got a FailedEntries row: {msg!r}"
    expected = ("ValidationException", f"RoleArn is required for target {sm_arn}.")
    assert (code, msg) == expected, f"expected {expected!r}, got {(code, msg)!r}"
    assert events.list_targets_by_rule(Rule=rule_name)["Targets"] == [], (
        "a refused PutTargets must not create the target at all -- "
        f"got {events.list_targets_by_rule(Rule=rule_name)['Targets']!r}"
    )

    # Positive control: supplying the target's OWN RoleArn succeeds, and the stored role is the
    # target's role, not the rule's -- proving RoleArn is never inherited from the rule.
    _put_targets_with_retry(ctx, events, rule_name, {"Id": "t1", "Arn": sm_arn, "RoleArn": target_role_arn})
    stored = _only_target(events, rule_name)
    assert stored["RoleArn"] == target_role_arn, (
        f"stored RoleArn must be the target's own role {target_role_arn!r}, not the rule's "
        f"{rule_role_arn!r}; got {stored['RoleArn']!r}"
    )

    # 2. An UPDATE that keeps the same Id and Arn but omits RoleArn must ALSO be refused, and must
    # leave the previously stored target byte-identical -- never merge in a null/absent role.
    kind, code, msg = _attempt_put_targets(events, rule_name, {"Id": "t1", "Arn": sm_arn})
    assert kind == "exception", f"expected a whole-request rejection, got a FailedEntries row: {msg!r}"
    expected = ("ValidationException", f"RoleArn is required for target {sm_arn}.")
    assert (code, msg) == expected, f"expected {expected!r}, got {(code, msg)!r}"
    after_same_arn = _only_target(events, rule_name)
    assert after_same_arn == stored, (
        f"a refused same-Arn update must leave the target unchanged; before {stored!r}, "
        f"after {after_same_arn!r}"
    )

    # 3. An UPDATE that changes the Arn and still omits RoleArn must likewise be refused, and must
    # leave the ORIGINAL target (original Arn, original role) unchanged -- the role is never
    # cleared by a refused write.
    changed_arn = sm_arn + "-changed"
    kind, code, msg = _attempt_put_targets(events, rule_name, {"Id": "t1", "Arn": changed_arn})
    assert kind == "exception", f"expected a whole-request rejection, got a FailedEntries row: {msg!r}"
    expected = ("ValidationException", f"RoleArn is required for target {changed_arn}.")
    assert (code, msg) == expected, f"expected {expected!r}, got {(code, msg)!r}"
    after_changed_arn = _only_target(events, rule_name)
    assert after_changed_arn == stored, (
        f"a refused Arn-changing update must leave the original target unchanged; "
        f"before {stored!r}, after {after_changed_arn!r}"
    )


_TRUST_EVENTS = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "events.amazonaws.com"}, "Action": "sts:AssumeRole"}],
})


def _create_events_role(ctx, iam, role_name: str) -> str:
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_EVENTS)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _put_rule_with_retry(ctx, events, name: str, pattern: str, role_arn: str, *, timeout_s: float = 80.0) -> None:
    """IAM role propagation has no condition to poll; retry boundedly on 'cannot be assumed'."""
    last: Exception | None = None
    deadline = time.monotonic() + timeout_s
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
    while time.monotonic() < deadline:
        try:
            events.put_rule(Name=name, EventPattern=pattern, RoleArn=role_arn)
            return
        except ClientError as exc:
            if "cannot be assumed" not in str(exc):
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"PutRule never accepted the role within {timeout_s}s: {last}")


def _put_targets_with_retry(ctx, events, rule: str, target: dict, *, timeout_s: float = 80.0) -> None:
    last: Exception | None = None
    deadline = time.monotonic() + timeout_s
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
    while time.monotonic() < deadline:
        try:
            resp = events.put_targets(Rule=rule, Targets=[target])
            assert resp["FailedEntryCount"] == 0, f"PutTargets failed entries: {resp.get('FailedEntries')!r}"
            return
        except ClientError as exc:
            if "cannot be assumed" not in str(exc):
                raise
            last = exc
            time.sleep(2)
    raise AssertionError(f"PutTargets never accepted the role within {timeout_s}s: {last}")


def _attempt_put_targets(events, rule: str, target: dict) -> tuple[str, str | None, str]:
    """PutTargets expected to be refused. Returns (kind, code, message); raises if accepted."""
    try:
        resp = events.put_targets(Rule=rule, Targets=[target])
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return ("exception", err.get("Code"), err.get("Message") or "")
    failed = resp.get("FailedEntries") or []
    if resp.get("FailedEntryCount"):
        return ("entry", failed[0].get("ErrorCode"), failed[0].get("ErrorMessage") or "")
    raise AssertionError(
        f"PutTargets ACCEPTED a target missing a required RoleArn: {target!r}; response was {resp!r}"
    )


def _only_target(events, rule: str) -> dict:
    targets = events.list_targets_by_rule(Rule=rule)["Targets"]
    assert len(targets) == 1, f"expected exactly one target on {rule!r}, got {targets!r}"
    return targets[0]


def _remove_targets_quietly(events, rule: str) -> None:
    """DeleteRule rejects a rule that still has targets (``Force`` only waives that check for a
    rule a service created on your behalf, never for one you own) -- remove them first."""
    ids = [t["Id"] for t in events.list_targets_by_rule(Rule=rule).get("Targets", [])]
    if ids:
        events.remove_targets(Rule=rule, Ids=ids)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
