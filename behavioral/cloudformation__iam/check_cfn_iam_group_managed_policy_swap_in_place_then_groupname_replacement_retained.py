"""cfn-iam-group-managed-policy-swap-in-place-then-groupname-replacement-retained."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-group-managed-policy-swap-in-place-then-groupname-replacement-retained"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam"]

#: A stack transition takes seconds to a few minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
#: An attachment reaches the policy simulator within seconds; the cap only stops a hung poll.
_SIM_CAP_S = 90.0
#: A delete reaches every independent read within seconds; the cap only stops a hung poll.
_READ_CAP_S = 90.0
_NAMED_IAM = ["CAPABILITY_NAMED_IAM"]
_REPLACE_REASON = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
_ACTIONS = ["s3:GetObject", "s3:PutObject"]


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c7",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An AWS::IAM::Group's ManagedPolicyArns and Path round-trip through IAM and change the
    simulator's grant for the group; swapping the attached policy is in place, a GroupName
    change replaces the group under Retain, and DeleteStack removes only the replacement.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-group.html
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")

    stack_name = ctx.unique_name("sim2real-cfnreal-grp-")
    group_a = ctx.unique_name("sim2real-cfnreal-grp-a-")
    group_b = ctx.unique_name("sim2real-cfnreal-grp-b-")

    # The two attachable policies are the check's own, outside the stack, so a group the stack
    # orphans under Retain can go on holding one without blocking a later DeleteStack.
    read_arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-cfnreal-grppol-read-"),
        PolicyDocument=json.dumps(_statement("s3:GetObject")),
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: _retire_policy(iam, read_arn))
    write_arn = iam.create_policy(
        PolicyName=ctx.unique_name("sim2real-cfnreal-grppol-write-"),
        PolicyDocument=json.dumps(_statement("s3:PutObject")),
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: _retire_policy(iam, write_arn))
    ctx.on_cleanup(lambda: _retire_group(iam, group_a))
    ctx.on_cleanup(lambda: _retire_stack(cfn, stack_name))

    # ---- 1. create: the group reads, the simulator grants exactly the read action -----------
    stack_id = cfn.create_stack(
        StackName=stack_name,
        Capabilities=_NAMED_IAM,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        TemplateBody=_body(group_a, "/sim2real/a/", read_arn),
    )["StackId"]
    stack = _settle(ctx, cfn, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    _assert_tracked(cfn, stack_id, "Group", group_a)

    group = iam.get_group(GroupName=group_a)["Group"]
    group_id = group["GroupId"]
    assert group["Path"] == "/sim2real/a/", f"GetGroup.Path was {group.get('Path')!r}"
    attached = {p["PolicyArn"] for p in iam.list_attached_group_policies(GroupName=group_a)["AttachedPolicies"]}
    assert attached == {read_arn}, f"ListAttachedGroupPolicies returned {attached!r}"
    _assert_grants(ctx, iam, group_a, {"s3:GetObject": "allowed", "s3:PutObject": "implicitDeny"})

    # ---- 2. in place: swap the attached policy; the identity and path are untouched ---------
    rows = _update(
        ctx, cfn, stack_id, "Group", _body(group_a, "/sim2real/a/", write_arn), Capabilities=_NAMED_IAM,
    )
    _assert_in_place(rows, group_a)
    group = iam.get_group(GroupName=group_a)["Group"]
    assert group["GroupId"] == group_id, f"swapping the policy must keep GroupId, got {group!r}"
    attached = {p["PolicyArn"] for p in iam.list_attached_group_policies(GroupName=group_a)["AttachedPolicies"]}
    assert attached == {write_arn}, f"ListAttachedGroupPolicies after the swap returned {attached!r}"
    _assert_grants(ctx, iam, group_a, {"s3:GetObject": "implicitDeny", "s3:PutObject": "allowed"})

    # ---- 3. GroupName is create-only: a new name replaces the group; Retain keeps the old ---
    rows = _update(
        ctx, cfn, stack_id, "Group", _body(group_b, "/sim2real/a/", write_arn), Capabilities=_NAMED_IAM,
    )
    _assert_replaced(rows, group_a, group_b)
    _assert_tracked(cfn, stack_id, "Group", group_b)

    new_group = iam.get_group(GroupName=group_b)["Group"]
    assert new_group["GroupId"] != group_id, f"a replacement must mint a new GroupId, got {new_group!r}"
    new_attached = {p["PolicyArn"] for p in iam.list_attached_group_policies(GroupName=group_b)["AttachedPolicies"]}
    assert new_attached == {write_arn}, f"the replacement's attachment was {new_attached!r}"
    _assert_grants(ctx, iam, group_b, {"s3:GetObject": "implicitDeny", "s3:PutObject": "allowed"})

    old_group = iam.get_group(GroupName=group_a)["Group"]
    assert old_group["GroupId"] == group_id, (
        f"the retained group must still be {group_id!r}, got {old_group['GroupId']!r}"
    )

    # ---- 4. DeleteStack removes the replacement's attachment and group, not the retained one -
    _destroy(ctx, cfn, stack_id)
    _await_gone(ctx, lambda: iam.get_group(GroupName=group_b), "NoSuchEntity",
                f"The group with name {group_b} cannot be found.")
    survivor = iam.get_group(GroupName=group_a)["Group"]
    assert survivor["GroupId"] == group_id, "the retained group must survive DeleteStack"
    survivor_attached = {
        p["PolicyArn"] for p in iam.list_attached_group_policies(GroupName=group_a)["AttachedPolicies"]
    }
    assert survivor_attached == {write_arn}, (
        f"the retained group's attachment must be untouched by the delete, got {survivor_attached!r}"
    )


def _statement(action: str) -> dict:
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}]}


def _body(name: str, path: str, policy_arn: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {
                "Type": "AWS::IAM::Group",
                "UpdateReplacePolicy": "Retain",
                "Properties": {
                    "GroupName": name,
                    "Path": path,
                    "ManagedPolicyArns": [policy_arn],
                },
            },
        },
    })


def _stack(cfn, stack_id: str) -> dict:
    return cfn.describe_stacks(StackName=stack_id)["Stacks"][0]


def _budget_s(ctx, cap_s: float) -> float:
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _settle(ctx, cfn, stack_id: str) -> dict:
    """The stack once nothing is `*_IN_PROGRESS` on it."""
    deadline = time.monotonic() + _budget_s(ctx, _STACK_CAP_S)
    while True:
        s = _stack(cfn, stack_id)
        if not s["StackStatus"].endswith("_IN_PROGRESS"):
            return s
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {stack_id!r} never settled; last {s['StackStatus']!r}")
        time.sleep(2.0)


def _physical(cfn, stack_id: str, logical_id: str) -> str:
    return cfn.describe_stack_resource(StackName=stack_id, LogicalResourceId=logical_id)[
        "StackResourceDetail"
    ]["PhysicalResourceId"]


def _assert_tracked(cfn, stack_id: str, logical_id: str, expected: str) -> None:
    got = _physical(cfn, stack_id, logical_id)
    assert got == expected, f"stack must track {logical_id} as {expected!r}, got {got!r}"


def _events_since(cfn, stack_id: str, after: int) -> list[dict]:
    rows: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        rows.extend(page["StackEvents"])
    return rows[::-1][after:]


def _update(ctx, cfn, stack_id: str, logical_id: str, body: str, **kw) -> list[tuple]:
    """UpdateStack to ``body``, require UPDATE_COMPLETE, return ``logical_id``'s event rows."""
    before = len(_events_since(cfn, stack_id, 0))
    cfn.update_stack(StackName=stack_id, TemplateBody=body, **kw)
    stack = _settle(ctx, cfn, stack_id)
    rows = _events_since(cfn, stack_id, before)
    assert stack["StackStatus"] == "UPDATE_COMPLETE", (
        f"update ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}; "
        f"events {[(r['LogicalResourceId'], r['ResourceStatus']) for r in rows]!r}"
    )
    return [
        (r["ResourceStatus"], r.get("ResourceStatusReason"), r.get("PhysicalResourceId"))
        for r in rows if r["LogicalResourceId"] == logical_id
    ]


def _row_sequence_holds(rows: list[tuple], wanted: list[tuple]) -> bool:
    remaining = list(rows)
    for want in wanted:
        found = False
        for i, row in enumerate(remaining):
            if all(w is None or w == v for w, v in zip(want, row, strict=True)):
                remaining = remaining[i + 1:]
                found = True
                break
        if not found:
            return False
    return True


def _assert_in_place(rows: list[tuple], physical: str) -> None:
    assert _row_sequence_holds(
        rows, [("UPDATE_IN_PROGRESS", None, None), ("UPDATE_COMPLETE", None, physical)]
    ), f"an in-place update must progress and complete on {physical!r}: {rows!r}"
    replacing = [r for r in rows if r[1] == _REPLACE_REASON or r[0].startswith("DELETE_")]
    assert replacing == [], f"this update must not replace or delete anything: {replacing!r}"


def _assert_replaced(rows: list[tuple], old: str, new: str) -> None:
    assert _row_sequence_holds(
        rows,
        [
            ("UPDATE_IN_PROGRESS", _REPLACE_REASON, None),
            ("UPDATE_COMPLETE", None, new),
            ("DELETE_SKIPPED", None, old),
        ],
    ), f"a GroupName change must replace to {new!r} and skip deleting {old!r}: {rows!r}"
    deleted = [r for r in rows if r[0] in ("DELETE_IN_PROGRESS", "DELETE_COMPLETE")]
    assert deleted == [], f"UpdateReplacePolicy Retain must delete nothing: {deleted!r}"


def _destroy(ctx, cfn, stack_id: str) -> None:
    cfn.delete_stack(StackName=stack_id)
    stack = _settle(ctx, cfn, stack_id)
    assert stack["StackStatus"] == "DELETE_COMPLETE", (
        f"DeleteStack ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )


def _await_gone(ctx, fn, want_code: str, want_message: str) -> None:
    """Poll ``fn`` until it fails with IAM's exact not-found pair; a lingering success retries."""
    deadline = time.monotonic() + _budget_s(ctx, _READ_CAP_S)
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = (err.get("Code"), err.get("Message") or "")
            assert got == (want_code, want_message), f"expected {(want_code, want_message)!r}, got {got!r}"
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"still answering after the delete: {result!r}")
        time.sleep(2.0)


def _decisions(iam, group_name: str) -> dict:
    group_arn = iam.get_group(GroupName=group_name)["Group"]["Arn"]
    results = iam.simulate_principal_policy(
        PolicySourceArn=group_arn, ActionNames=_ACTIONS
    )["EvaluationResults"]
    return {r["EvalActionName"]: r["EvalDecision"] for r in results}


def _assert_grants(ctx, iam, group_name: str, want: dict) -> None:
    """Behaviour: the simulator evaluates the group's attached policy to exactly ``want``."""
    deadline = time.monotonic() + _budget_s(ctx, _SIM_CAP_S)
    while True:
        got = _decisions(iam, group_name)
        if got == want:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"simulated decisions for {group_name!r} never reached {want!r}, last {got!r}")
        time.sleep(2.0)


def _retire_group(iam, name: str) -> None:
    try:
        for p in iam.list_attached_group_policies(GroupName=name)["AttachedPolicies"]:
            iam.detach_group_policy(GroupName=name, PolicyArn=p["PolicyArn"])
        iam.delete_group(GroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _retire_policy(iam, arn: str) -> None:
    try:
        for e in iam.list_entities_for_policy(PolicyArn=arn)["PolicyGroups"]:
            iam.detach_group_policy(GroupName=e["GroupName"], PolicyArn=arn)
        iam.delete_policy(PolicyArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _retire_stack(cfn, stack_name: str) -> None:
    try:
        stack_id = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]
    except ClientError as exc:
        if f"Stack with id {stack_name} does not exist" in str(exc):
            return
        raise
    status = _stack(cfn, stack_id)["StackStatus"]
    while status.endswith("_IN_PROGRESS"):
        time.sleep(2.0)
        status = _stack(cfn, stack_id)["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    while True:
        status = _stack(cfn, stack_id)["StackStatus"]
        if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
            break
        time.sleep(2.0)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"teardown stack {stack_id} ended {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
