"""cfn-events-rule-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-events-rule-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "events"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
_SOURCE = "sim2real.reality"


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c7",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An AWS::Events::Rule survives create, in-place update, retained replacement and delete.

    DescribeRule reads back each template and its stored pattern matches only its detail-type; a
    new pattern applies in place; a Name change under Retain keeps the old rule; deletion is gone.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-events-rule.html
    """
    cfn = ctx.client("cloudformation")
    events = ctx.client("events")

    stack_name = ctx.unique_name("sim2real-cfnreal-rule-")
    rule_v1 = ctx.unique_name("sim2real-cfnreal-rule-a-")
    rule_v2 = ctx.unique_name("sim2real-cfnreal-rule-b-")

    # The replaced rule outlives the stack, so the check deletes it itself.
    ctx.on_cleanup(lambda: _delete_rule(events, rule_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, EventBridge view, behaviour ------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(rule_v1, "first", "ENABLED"), Tags=_TAGS
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    _assert_tracks(cfn, stack_id, "Rule", rule_v1)
    rule = _assert_rule(events, rule_v1, "first", "ENABLED")
    _assert_matches(ctx, events, rule, "first", "second")

    # ---- 2. in-place update of the mutable EventPattern and State ---------------------------
    rows = _update(ctx, cfn, stack_id, "Rule", _template(rule_v1, "second", "DISABLED"))
    _assert_updated_in_place(rows, rule_v1)
    _assert_tracks(cfn, stack_id, "Rule", rule_v1)
    updated = _assert_rule(events, rule_v1, "second", "DISABLED")
    assert updated["Arn"] == rule["Arn"], f"an in-place update keeps the rule: {updated!r}"
    _assert_matches(ctx, events, updated, "second", "first")

    # ---- 3. Name forces replacement; UpdateReplacePolicy Retain keeps the old one -----------
    rows = _update(ctx, cfn, stack_id, "Rule", _template(rule_v2, "second", "DISABLED"))
    _assert_replaced_and_retained(rows, rule_v1, rule_v2)
    _assert_tracks(cfn, stack_id, "Rule", rule_v2)
    new = _assert_rule(events, rule_v2, "second", "DISABLED")
    _assert_matches(ctx, events, new, "second", "first")
    _assert_rule(events, rule_v1, "second", "DISABLED")

    # ---- 4. DeleteStack: the rule it owns is gone -------------------------------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    got = _error(lambda: events.describe_rule(Name=rule_v2))
    want = ("ResourceNotFoundException", f"Rule {rule_v2} does not exist on EventBus default.")
    assert got == want, f"DescribeRule after DeleteStack: {got!r}, expected {want!r}"
    _assert_rule(events, rule_v1, "second", "DISABLED")


def _pattern(detail_type: str) -> dict:
    return {"source": [_SOURCE], "detail-type": [detail_type]}


def _template(name: str, detail_type: str, state: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Rule": {
                    "Type": "AWS::Events::Rule",
                    # Name is create-only, so a new name replaces the rule.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Name": name,
                        "Description": "reality check rule",
                        "EventPattern": _pattern(detail_type),
                        "State": state,
                    },
                },
            },
        }
    )


def _assert_rule(events, name: str, detail_type: str, state: str) -> dict:
    """EventBridge's view: the rule on the default bus holds the templated properties."""
    rule = events.describe_rule(Name=name)
    got = (
        rule["Name"],
        rule["EventBusName"],
        rule["Description"],
        rule["State"],
        json.loads(rule["EventPattern"]),
    )
    want = (name, "default", "reality check rule", state, _pattern(detail_type))
    assert got == want, f"DescribeRule {name!r}: {got!r}, expected {want!r}"
    return rule


def _event(ctx, detail_type: str) -> str:
    return json.dumps(
        {
            "id": "6a7e8feb-b491-4cf7-a9f1-bf3703467718",
            "detail-type": detail_type,
            "source": _SOURCE,
            "account": ctx.account,
            "time": "2026-01-01T00:00:00Z",
            "region": ctx.region,
            "resources": [],
            "detail": {},
        }
    )


def _assert_matches(ctx, events, rule: dict, hit: str, miss: str) -> None:
    """Behaviour: the rule's stored pattern matches its own detail-type and not another."""
    pattern = rule["EventPattern"]
    for detail_type, want in ((hit, True), (miss, False)):
        got = events.test_event_pattern(EventPattern=pattern, Event=_event(ctx, detail_type))
        assert got["Result"] is want, (
            f"the stored pattern of {rule['Name']!r} on detail-type {detail_type!r}: {got!r}"
        )


def _delete_rule(events, name: str) -> None:
    try:
        events.delete_rule(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


# ===== stack helpers =====


def _budget_s(ctx, cap_s: float) -> float:
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx) -> bool:
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, done, *, cap_s: float, what: str, interval_s: float = 2.0):
    """Call probe() until done(result) holds and return it; ctx=None (teardown) is not budgeted."""
    timeout_s = cap_s if ctx is None else _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while waiting for {what}; not graded")
            raise AssertionError(f"{what} not reached within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises; a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _settle(ctx, cfn, stack_id: str) -> dict:
    """The stack once no operation (cleanup phase included) is in progress on it."""
    return _poll(
        ctx,
        lambda: _stack(cfn, stack_id),
        lambda s: not s["StackStatus"].endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled",
    )


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _assert_tracks(cfn, stack_id: str, logical_id: str, expected: str) -> None:
    """CloudFormation's view: the stack resource carries the expected PhysicalResourceId."""
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"the stack must track {logical_id} as {expected!r}, got {got!r}"


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first (the API pages newest first)."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return out[::-1]


def _update(ctx, cfn, stack_id: str, logical_id: str, body: str, **kw) -> list[tuple]:
    """UpdateStack to body, assert UPDATE_COMPLETE and return the update's rows for logical_id.

    A row is (ResourceStatus, ResourceStatusReason, PhysicalResourceId), oldest first.
    """
    before = len(_events(cfn, stack_id))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, **kw)
    stack = _settle(ctx, cfn, stack_id)
    events = _events(cfn, stack_id)[before:]
    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in events
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; {failed!r}"
    )
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["LogicalResourceId"] == logical_id
    ]


def _in_order(rows: list[tuple], wanted: list[tuple]) -> bool:
    """Whether every wanted row occurs in rows in that order; a None field matches any value."""
    remaining = iter(rows)
    return all(
        any(all(w is None or w == v for w, v in zip(want, row, strict=True)) for row in remaining)
        for want in wanted
    )


def _assert_updated_in_place(rows: list[tuple], physical: str) -> None:
    """The update completed on the same physical id and reported no replacement or delete."""
    assert _in_order(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACING or r[0].startswith("DELETE_")]
    assert replacing == [], f"an in-place update must not replace anything: {replacing!r}"


def _assert_replaced_and_retained(rows: list[tuple], old: str, new: str) -> None:
    """The update reported a replacement, completed on the new id and skipped deleting the old."""
    assert _in_order(
        rows,
        [
            ("UPDATE_IN_PROGRESS", _REPLACING, None),
            ("UPDATE_COMPLETE", None, new),
            ("DELETE_SKIPPED", None, old),
        ],
    ), (
        f"the replacement must report creating a new resource, complete as {new!r} and skip "
        f"deleting {old!r} (UpdateReplacePolicy Retain), in that order: {rows!r}"
    )
    deleted = [r for r in rows if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing: {deleted!r}"


def _delete_and_confirm(ctx, cfn, stack_id: str) -> None:
    """DeleteStack by StackId and assert it reaches DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        ctx,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    assert final == "DELETE_COMPLETE", (
        f"DeleteStack ended {final!r}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
    )


def _delete_stack(cfn, stack_name: str) -> None:
    """Teardown: delete the stack by its StackId and wait; DELETE_FAILED or a timeout raises."""
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if exc.response["Error"].get("Message") == f"Stack with id {stack_name} does not exist":
            return
        raise
    status = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: not s.endswith("_IN_PROGRESS"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} settled before teardown",
    )
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    final = _poll(
        None,
        lambda: _stack(cfn, stack_id)["StackStatus"],
        lambda s: s in ("DELETE_COMPLETE", "DELETE_FAILED"),
        cap_s=_STACK_S,
        what=f"stack {stack_id} deleted",
    )
    if final != "DELETE_COMPLETE":
        raise AssertionError(
            f"stack {stack_id} ended {final}: {_stack(cfn, stack_id).get('StackStatusReason')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
