"""cfn-iam-role-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-role-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "sts"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: A trust policy reaches STS within seconds; the bound only stops a hung poll.
_TRUST_S = 90.0
#: A change or delete reaches every read within seconds; the bound only stops a hung poll.
_PROPAGATE_S = 60.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_NAMED_IAM = ["CAPABILITY_NAMED_IAM"]
_REPLACING = (
    "Requested update requires the creation of a new physical resource; hence creating one."
)
_SESSION = "sim2real-cfnreal-role"


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c7",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """An AWS::IAM::Role survives create, in-place updates, retained replacement and delete.

    GetRole reads back each template: a PermissionsBoundary added then removed and a new trust
    policy keep the RoleId; a RoleName change under UpdateReplacePolicy Retain keeps the old role.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-role.html
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    partition = sts.get_caller_identity()["Arn"].split(":")[1]

    stack_name = ctx.unique_name("sim2real-cfnreal-role-")
    role_v1 = ctx.unique_name("sim2real-cfnreal-role-a-")
    role_v2 = ctx.unique_name("sim2real-cfnreal-role-b-")
    boundary_name = ctx.unique_name("sim2real-cfnreal-boundary-")
    external_id = ctx.unique_name("sim2real-ext-")
    open_trust = _trust(partition, ctx.account, None)
    gated_trust = _trust(partition, ctx.account, external_id)

    # The replaced role outlives the stack, so the check deletes it itself.
    ctx.on_cleanup(lambda: _delete_role(iam, role_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, IAM view, behaviour --------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name,
        Capabilities=_NAMED_IAM,
        Tags=_TAGS,
        TemplateBody=_template(role_v1, boundary_name, open_trust, 3600, boundary=False),
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    _assert_tracks(cfn, stack_id, "Role", role_v1)
    boundary_arn = _physical(cfn, stack_id, "Boundary")
    assert boundary_arn == f"arn:{partition}:iam::{ctx.account}:policy/{boundary_name}", (
        f"the boundary policy's physical id is its ARN, got {boundary_arn!r}"
    )
    role = _role(iam, role_v1)
    assert (role["AssumeRolePolicyDocument"], role["MaxSessionDuration"], role["Description"]) == (
        open_trust,
        3600,
        "reality check role",
    ), f"GetRole must read back the templated role, got {role!r}"
    assert "PermissionsBoundary" not in role, f"no boundary was templated, got {role!r}"
    role_id = role["RoleId"]
    _assume(ctx, sts, role["Arn"], role_id, None)

    # ---- 2a. in place: add a PermissionsBoundary and raise MaxSessionDuration ---------------
    body = _template(role_v1, boundary_name, open_trust, 7200, boundary=True)
    _assert_updated_in_place(
        _update(ctx, cfn, stack_id, "Role", body, Capabilities=_NAMED_IAM), role_v1
    )
    role = _role(iam, role_v1)
    assert role.get("PermissionsBoundary") == {
        "PermissionsBoundaryType": "Policy",
        "PermissionsBoundaryArn": boundary_arn,
    }, f"the in-place update must attach the boundary, got {role.get('PermissionsBoundary')!r}"
    assert role["MaxSessionDuration"] == 7200, f"MaxSessionDuration 7200, got {role!r}"
    assert role["RoleId"] == role_id, f"an in-place update keeps the RoleId: {role!r}"

    # ---- 2b. in place: remove the PermissionsBoundary ---------------------------------------
    body = _template(role_v1, boundary_name, open_trust, 7200, boundary=False)
    _assert_updated_in_place(
        _update(ctx, cfn, stack_id, "Role", body, Capabilities=_NAMED_IAM), role_v1
    )
    role = _role(iam, role_v1)
    assert "PermissionsBoundary" not in role, (
        f"removing the property must detach the boundary, got {role.get('PermissionsBoundary')!r}"
    )
    assert role["RoleId"] == role_id, f"an in-place update keeps the RoleId: {role!r}"

    # ---- 2c. in place: require an ExternalId in the trust policy ----------------------------
    body = _template(role_v1, boundary_name, gated_trust, 7200, boundary=False)
    _assert_updated_in_place(
        _update(ctx, cfn, stack_id, "Role", body, Capabilities=_NAMED_IAM), role_v1
    )
    _assert_tracks(cfn, stack_id, "Role", role_v1)
    role = _role(iam, role_v1)
    assert role["AssumeRolePolicyDocument"] == gated_trust, (
        f"GetRole must read back the new trust policy, got {role['AssumeRolePolicyDocument']!r}"
    )
    assert role["RoleId"] == role_id, f"an in-place update keeps the RoleId: {role!r}"
    _assume(ctx, sts, role["Arn"], role_id, external_id)

    # ---- 3. RoleName forces replacement; UpdateReplacePolicy Retain keeps the old one -------
    body = _template(role_v2, boundary_name, gated_trust, 7200, boundary=False)
    rows = _update(ctx, cfn, stack_id, "Role", body, Capabilities=_NAMED_IAM)
    _assert_replaced_and_retained(rows, role_v1, role_v2)
    _assert_tracks(cfn, stack_id, "Role", role_v2)
    new = _role(iam, role_v2)
    assert (new["AssumeRolePolicyDocument"], new["MaxSessionDuration"]) == (gated_trust, 7200), (
        f"the replacement must carry the template's trust and duration, got {new!r}"
    )
    assert new["RoleId"] != role_id, f"a replacement is a new role, got RoleId {new['RoleId']!r}"
    _assume(ctx, sts, new["Arn"], new["RoleId"], external_id)
    old = _role(iam, role_v1)
    assert (old["RoleId"], old["AssumeRolePolicyDocument"]) == (role_id, gated_trust), (
        f"the retained role {role_v1!r} must be the original, unchanged, got {old!r}"
    )

    # ---- 4. DeleteStack: the role it owns is gone -------------------------------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    want = ("NoSuchEntity", f"The role with name {role_v2} cannot be found.")
    _await_error(ctx, lambda: iam.get_role(RoleName=role_v2), want, "GetRole after DeleteStack")
    assert _role(iam, role_v1)["RoleId"] == role_id, "the retained role survives DeleteStack"


def _trust(partition: str, account: str, external_id: str | None) -> dict:
    statement: dict = {
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:{partition}:iam::{account}:root"},
        "Action": "sts:AssumeRole",
    }
    if external_id is not None:
        statement["Condition"] = {"StringEquals": {"sts:ExternalId": external_id}}
    return {"Version": "2012-10-17", "Statement": [statement]}


def _template(
    role: str, boundary_name: str, trust: dict, max_session: int, *, boundary: bool
) -> str:
    props: dict = {
        "RoleName": role,
        "Description": "reality check role",
        "AssumeRolePolicyDocument": trust,
        "MaxSessionDuration": max_session,
    }
    if boundary:
        props["PermissionsBoundary"] = {"Ref": "Boundary"}
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Boundary": {
                    "Type": "AWS::IAM::ManagedPolicy",
                    "Properties": {
                        "ManagedPolicyName": boundary_name,
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "sts:GetCallerIdentity",
                                    "Resource": "*",
                                },
                            ],
                        },
                    },
                },
                "Role": {
                    "Type": "AWS::IAM::Role",
                    # RoleName is create-only, so a new name replaces the role.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": props,
                },
            },
        }
    )


def _role(iam, name: str) -> dict:
    return iam.get_role(RoleName=name)["Role"]


def _assume(ctx, sts, role_arn: str, role_id: str, external_id: str | None) -> None:
    """Behaviour: the caller assumes the role under its trust policy (retried on propagation)."""
    kwargs = {"RoleArn": role_arn, "RoleSessionName": _SESSION, "DurationSeconds": 900}
    if external_id is not None:
        kwargs["ExternalId"] = external_id

    def attempt():
        try:
            return sts.assume_role(**kwargs)["AssumedRoleUser"]["AssumedRoleId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            return None

    got = _poll(
        ctx,
        attempt,
        lambda r: r is not None,
        cap_s=_TRUST_S,
        what=f"AssumeRole on {role_arn} to be allowed",
    )
    assert got == f"{role_id}:{_SESSION}", f"the session must belong to {role_id!r}, got {got!r}"


def _delete_role(iam, name: str) -> None:
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _await_error(ctx, fn, want: tuple[str, str], what: str) -> None:
    """Poll fn until it is refused, then assert the exact (code, message) want.

    A delete reaches every read within seconds, so a call that still succeeds is retried.
    """
    timeout_s = _budget_s(ctx, _PROPAGATE_S)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            got = (err.get("Code"), err.get("Message") or "")
            assert got == want, f"{what}: {got!r}, expected {want!r}"
            return
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"the run budget ended while {what} still succeeded; not graded")
            raise AssertionError(f"{what} still succeeded after {timeout_s:.0f}s: {result!r}")
        time.sleep(2.0)


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
