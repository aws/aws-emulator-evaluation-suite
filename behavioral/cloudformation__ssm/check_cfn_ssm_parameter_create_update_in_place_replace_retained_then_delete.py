"""cfn-ssm-parameter-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-parameter-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "ssm"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
#: GetParameter on a missing name answers ParameterNotFound with no message.
_NOT_FOUND = ("ParameterNotFound", "")


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An AWS::SSM::Parameter survives create, in-place update, retained replacement and delete.

    SSM reads back the templated values; a Value change keeps the name (version 2, no replacement);
    a Name change under UpdateReplacePolicy Retain keeps the old one; deletion is ParameterNotFound.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ssm-parameter.html
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    stack_name = ctx.unique_name("sim2real-cfnreal-ssm-")
    prefix = "/" + ctx.unique_name("sim2real-cfnreal-ssm-")
    name_v1 = f"{prefix}/first"
    name_v2 = f"{prefix}/second"

    # The replaced parameter outlives the stack, so the check deletes it itself.
    ctx.on_cleanup(lambda: _delete_parameter(ssm, name_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, SSM view, behaviour --------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(name_v1, "value-one", "first description"),
        Tags=_TAGS,
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    _assert_tracks(cfn, stack_id, "Param", name_v1)
    param = ssm.get_parameter(Name=name_v1)["Parameter"]
    assert (param["Name"], param["Type"], param["Value"], param["Version"]) == (
        name_v1,
        "String",
        "value-one",
        1,
    ), f"SSM must hold the templated parameter at version 1, got {param!r}"
    description = _description(ssm, name_v1)
    assert description == "first description", f"templated Description, got {description!r}"
    by_path = ssm.get_parameters_by_path(Path=prefix)["Parameters"]
    assert [(p["Name"], p["Value"]) for p in by_path] == [(name_v1, "value-one")], (
        f"a path read under {prefix!r} must serve exactly the deployed parameter, got {by_path!r}"
    )

    # ---- 2. in-place update of the mutable Value and Description ----------------------------
    body = _template(name_v1, "value-two", "second description")
    _assert_updated_in_place(_update(ctx, cfn, stack_id, "Param", body), name_v1)
    _assert_tracks(cfn, stack_id, "Param", name_v1)
    param = ssm.get_parameter(Name=name_v1)["Parameter"]
    assert (param["Value"], param["Version"]) == ("value-two", 2), (
        f"the in-place update must write the new Value as version 2, got {param!r}"
    )
    description = _description(ssm, name_v1)
    assert description == "second description", f"updated Description, got {description!r}"
    history = [
        (h["Version"], h["Value"]) for h in ssm.get_parameter_history(Name=name_v1)["Parameters"]
    ]
    assert history == [(1, "value-one"), (2, "value-two")], (
        f"an in-place update keeps the parameter's history, got {history!r}"
    )

    # ---- 3. Name forces replacement; UpdateReplacePolicy Retain keeps the old one -----------
    body = _template(name_v2, "value-two", "second description")
    _assert_replaced_and_retained(_update(ctx, cfn, stack_id, "Param", body), name_v1, name_v2)
    _assert_tracks(cfn, stack_id, "Param", name_v2)
    new = ssm.get_parameter(Name=name_v2)["Parameter"]
    assert (new["Name"], new["Value"], new["Version"]) == (name_v2, "value-two", 1), (
        f"the replacement must be a new parameter at version 1 with the new name, got {new!r}"
    )
    old = ssm.get_parameter(Name=name_v1)["Parameter"]
    assert (old["Value"], old["Version"]) == ("value-two", 2), (
        f"the retained parameter {name_v1!r} must keep its value and version, got {old!r}"
    )

    # ---- 4. DeleteStack: the parameter it owns is gone --------------------------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    got = _error(lambda: ssm.get_parameter(Name=name_v2))
    assert got == _NOT_FOUND, f"GetParameter after DeleteStack: {got!r}, expected {_NOT_FOUND!r}"
    kept = ssm.get_parameter(Name=name_v1)["Parameter"]["Value"]
    assert kept == "value-two", f"the retained parameter must survive DeleteStack, got {kept!r}"


def _template(name: str, value: str, description: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Param": {
                    "Type": "AWS::SSM::Parameter",
                    # Name is create-only, so a new Name replaces the parameter.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "Name": name,
                        "Type": "String",
                        "Value": value,
                        "Description": description,
                    },
                },
            },
        }
    )


def _description(ssm, name: str) -> str | None:
    """The parameter's Description, read through DescribeParameters scoped to its exact name."""
    found = ssm.describe_parameters(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
    )["Parameters"]
    assert len(found) == 1, f"DescribeParameters for {name!r} returned {found!r}"
    return found[0].get("Description")


def _delete_parameter(ssm, name: str) -> None:
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
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
