"""cfn-iot-thing-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iot-thing-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iot"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: Attribute search follows a thing's writes within seconds; the bound only stops a hung poll.
_SEARCH_S = 60.0
#: DescribeThing's refusal of a thing that no longer exists; {account}:{name} is its owner and name.
_THING_GONE = ("ResourceNotFoundException", "Thing {account}:{name} not found.")
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An AWS::IoT::Thing survives create, in-place update, retained replacement and delete.

    IoT reads back the templated attributes and finds the thing by them; an attribute change keeps
    the thing; a ThingName change under UpdateReplacePolicy Retain keeps the old thing too.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iot-thing.html
    """
    cfn = ctx.client("cloudformation")
    iot = ctx.client("iot")

    stack_name = ctx.unique_name("sim2real-cfnreal-iot-thing-")
    thing_v1 = ctx.unique_name("sim2real-cfnreal-thing-a-")
    thing_v2 = ctx.unique_name("sim2real-cfnreal-thing-b-")
    # One attribute value only this run's things carry, so the registry search is scoped to them.
    run_id = ctx.unique_name("run-")
    red = {"run": run_id, "color": "red"}
    blue = {"run": run_id, "color": "blue"}

    # The replaced thing outlives the stack, so the check deletes it itself.
    ctx.on_cleanup(lambda: _delete_thing(iot, ctx.account, thing_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, IoT view, behaviour --------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(thing_v1, red), Tags=_TAGS
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    _assert_tracks(cfn, stack_id, "Thing", thing_v1)
    thing = iot.describe_thing(thingName=thing_v1)
    assert thing["attributes"] == red, f"templated attributes {red!r}, got {thing!r}"
    outputs = _outputs(cfn, stack_id)
    assert outputs == {"Arn": thing["thingArn"], "Id": thing["thingId"]}, (
        f"GetAtt Arn and Id must be DescribeThing's thingArn and thingId: {outputs!r} vs {thing!r}"
    )
    thing_id = thing["thingId"]
    _assert_found(ctx, iot, run_id, {thing_v1: red})

    # ---- 2. in-place update of the mutable AttributePayload ---------------------------------
    rows = _update(ctx, cfn, stack_id, "Thing", _template(thing_v1, blue))
    _assert_updated_in_place(rows, thing_v1)
    _assert_tracks(cfn, stack_id, "Thing", thing_v1)
    thing = iot.describe_thing(thingName=thing_v1)
    assert thing["attributes"] == blue, f"updated attributes {blue!r}, got {thing!r}"
    assert thing["thingId"] == thing_id, (
        f"an in-place update keeps the thing: thingId {thing_id!r} -> {thing['thingId']!r}"
    )
    _assert_found(ctx, iot, run_id, {thing_v1: blue})

    # ---- 3. ThingName forces replacement; UpdateReplacePolicy Retain keeps the old thing ----
    rows = _update(ctx, cfn, stack_id, "Thing", _template(thing_v2, blue))
    _assert_replaced_and_retained(rows, thing_v1, thing_v2)
    _assert_tracks(cfn, stack_id, "Thing", thing_v2)
    new = iot.describe_thing(thingName=thing_v2)
    assert new["attributes"] == blue, f"the replacement carries {blue!r}, got {new!r}"
    assert new["thingId"] != thing_id, f"the replacement is a new thing, got thingId {thing_id!r}"
    old = iot.describe_thing(thingName=thing_v1)
    assert (old["thingId"], old["attributes"]) == (thing_id, blue), (
        f"the retained thing keeps its id {thing_id!r} and attributes {blue!r}: {old!r}"
    )
    _assert_found(ctx, iot, run_id, {thing_v1: blue, thing_v2: blue})

    # ---- 4. DeleteStack: the thing it owns is gone, the retained one stays ------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    gone = (_THING_GONE[0], _THING_GONE[1].format(account=ctx.account, name=thing_v2))
    got = _poll(
        ctx,
        lambda: _refusal(lambda: iot.describe_thing(thingName=thing_v2)),
        lambda e: e[0] != "<exists>",
        cap_s=_SEARCH_S,
        what=f"DescribeThing of {thing_v2!r} refused after DeleteStack",
    )
    assert got == gone, f"DescribeThing after DeleteStack: {got!r}, not {gone!r}"
    assert iot.describe_thing(thingName=thing_v1)["thingId"] == thing_id, (
        "the retained thing must survive DeleteStack"
    )
    _assert_found(ctx, iot, run_id, {thing_v1: blue})


def _template(name: str, attributes: dict) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Thing": {
                    "Type": "AWS::IoT::Thing",
                    # ThingName is create-only, so a new name replaces the thing.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "ThingName": name,
                        "AttributePayload": {"Attributes": attributes},
                    },
                },
            },
            "Outputs": {
                "Arn": {"Value": {"Fn::GetAtt": ["Thing", "Arn"]}},
                "Id": {"Value": {"Fn::GetAtt": ["Thing", "Id"]}},
            },
        }
    )


def _outputs(cfn, stack_id: str) -> dict:
    stack = _stack(cfn, stack_id)
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _found(iot, run_id: str) -> dict:
    """Behaviour: every thing the registry finds by the run's attribute, name -> attributes."""
    out: dict = {}
    kwargs = {"attributeName": "run", "attributeValue": run_id}
    while True:
        page = iot.list_things(**kwargs)
        out.update({t["thingName"]: t.get("attributes") for t in page.get("things", [])})
        if not page.get("nextToken"):
            return out
        kwargs["nextToken"] = page["nextToken"]


def _assert_found(ctx, iot, run_id: str, expected: dict) -> None:
    _poll(
        ctx,
        lambda: _found(iot, run_id),
        lambda f: f == expected,
        cap_s=_SEARCH_S,
        what=f"ListThings by run attribute finding exactly {expected!r}",
    )


def _refusal(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn raises, or an <exists> pair while it succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    return "<exists>", "the call still succeeds"


def _delete_thing(iot, account: str, name: str) -> None:
    """Teardown: delete the thing; a refused delete passes only if DescribeThing refuses it too."""
    try:
        iot.delete_thing(thingName=name)
    except ClientError:
        gone = (_THING_GONE[0], _THING_GONE[1].format(account=account, name=name))
        if _refusal(lambda: iot.describe_thing(thingName=name)) != gone:
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
