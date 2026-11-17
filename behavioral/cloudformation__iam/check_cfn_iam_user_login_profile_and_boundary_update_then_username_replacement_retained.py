"""cfn-iam-user-login-profile-and-boundary-update-then-username-replacement-retained."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-user-login-profile-and-boundary-update-then-username-replacement-retained"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam"]

#: A stack transition takes seconds to a few minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
#: A delete reaches every independent read within seconds; the cap only stops a hung poll.
_READ_CAP_S = 90.0
_NAMED_IAM = ["CAPABILITY_NAMED_IAM"]
_REPLACE_REASON = (
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
    """An AWS::IAM::User's LoginProfile, PermissionsBoundary, Path and Tags round-trip through
    IAM, survive an in-place update, and a UserName change replaces the user while Retain
    keeps the original; DeleteStack then removes the login profile with the replacement.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-user.html
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")

    stack_name = ctx.unique_name("sim2real-cfnreal-usr-")
    boundary_name = ctx.unique_name("sim2real-cfnreal-usrbnd-")
    user_a = ctx.unique_name("sim2real-cfnreal-usr-a-")
    user_b = ctx.unique_name("sim2real-cfnreal-usr-b-")
    tag_value = ctx.unique_name("sim2real-cfnreal-usrtag-")
    pw1 = f"Aa1!{ctx.unique_name('Pw')}"
    pw2 = f"Bb2@{ctx.unique_name('Pw')}"

    ctx.on_cleanup(lambda: _retire_user(iam, user_a))
    ctx.on_cleanup(lambda: _retire_stack(cfn, stack_name))

    # ---- 1. create: boundary attached, reset required, original path -----------------------
    stack_id = cfn.create_stack(
        StackName=stack_name,
        Capabilities=_NAMED_IAM,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        TemplateBody=_body(user_a, "/sim2real/a/", boundary_name, tag_value, pw1, True, True),
    )["StackId"]
    stack = _settle(ctx, cfn, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {stack['StackStatus']!r}: {stack.get('StackStatusReason')!r}"
    )
    boundary_arn = _physical(cfn, stack_id, "Boundary")
    _assert_tracked(cfn, stack_id, "User", user_a)

    user = iam.get_user(UserName=user_a)["User"]
    user_id = user["UserId"]
    assert user["Path"] == "/sim2real/a/", f"GetUser.Path was {user.get('Path')!r}"
    assert user.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn") == boundary_arn, (
        f"GetUser.PermissionsBoundary was {user.get('PermissionsBoundary')!r}, want {boundary_arn!r}"
    )
    # CloudFormation propagates the stack's own Tags onto every taggable resource, alongside
    # the template's own Tags property.
    tags_got = {(t["Key"], t["Value"]) for t in iam.list_user_tags(UserName=user_a)["Tags"]}
    assert tags_got == {("team", tag_value), ("sim2real", CHECK)}, f"ListUserTags returned {tags_got!r}"
    profile = iam.get_login_profile(UserName=user_a)["LoginProfile"]
    assert profile["PasswordResetRequired"] is True, f"GetLoginProfile was {profile!r}"

    # ---- 2. in place: drop the boundary, clear the reset flag, rotate the password ----------
    rows = _update(
        ctx, cfn, stack_id, "User",
        _body(user_a, "/sim2real/a/", boundary_name, tag_value, pw2, False, False),
        Capabilities=_NAMED_IAM,
    )
    _assert_in_place(rows, user_a)
    user = iam.get_user(UserName=user_a)["User"]
    assert "PermissionsBoundary" not in user, f"boundary must be detached, got {user!r}"
    assert user["UserId"] == user_id, f"an in-place update must keep UserId, got {user!r}"
    profile = iam.get_login_profile(UserName=user_a)["LoginProfile"]
    assert profile["PasswordResetRequired"] is False, f"GetLoginProfile was {profile!r}"

    # ---- 3. in place: move the path, a second mutable property on the same identity ---------
    rows = _update(
        ctx, cfn, stack_id, "User",
        _body(user_a, "/sim2real/moved/", boundary_name, tag_value, pw2, False, False),
        Capabilities=_NAMED_IAM,
    )
    _assert_in_place(rows, user_a)
    user = iam.get_user(UserName=user_a)["User"]
    assert user["Path"] == "/sim2real/moved/", f"GetUser.Path after the move was {user.get('Path')!r}"
    assert user["UserId"] == user_id, f"moving Path must keep UserId, got {user!r}"

    # ---- 4. UserName is create-only: a new name replaces the user; Retain keeps the old -----
    rows = _update(
        ctx, cfn, stack_id, "User",
        _body(user_b, "/sim2real/moved/", boundary_name, tag_value, pw2, False, False),
        Capabilities=_NAMED_IAM,
    )
    _assert_replaced(rows, user_a, user_b)
    _assert_tracked(cfn, stack_id, "User", user_b)

    new_user = iam.get_user(UserName=user_b)["User"]
    assert new_user["UserId"] != user_id, f"a replacement must mint a new UserId, got {new_user!r}"
    assert new_user["Path"] == "/sim2real/moved/", f"the replacement's Path was {new_user.get('Path')!r}"
    new_profile = iam.get_login_profile(UserName=user_b)["LoginProfile"]
    assert new_profile["PasswordResetRequired"] is False, f"GetLoginProfile was {new_profile!r}"

    old_user = iam.get_user(UserName=user_a)["User"]
    assert old_user["UserId"] == user_id, (
        f"the retained user must still be {user_id!r}, got {old_user['UserId']!r}"
    )

    # ---- 5. DeleteStack removes the replacement's login profile and account, not the retained one
    _destroy(ctx, cfn, stack_id)
    _await_gone(ctx, lambda: iam.get_user(UserName=user_b), "NoSuchEntity",
                f"The user with name {user_b} cannot be found.")
    _await_gone(ctx, lambda: iam.get_login_profile(UserName=user_b), "NoSuchEntity",
                f"The user with name {user_b} cannot be found.")
    assert iam.get_user(UserName=user_a)["User"]["UserId"] == user_id, (
        "the retained user must survive DeleteStack"
    )


def _body(
    name: str, path: str, boundary_name: str, tag_value: str, password: str,
    reset_required: bool, attach_boundary: bool,
) -> str:
    props: dict = {
        "UserName": name,
        "Path": path,
        "LoginProfile": {"Password": password, "PasswordResetRequired": reset_required},
        "Tags": [{"Key": "team", "Value": tag_value}],
    }
    if attach_boundary:
        props["PermissionsBoundary"] = {"Ref": "Boundary"}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Boundary": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "ManagedPolicyName": boundary_name,
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Action": "sts:GetCallerIdentity", "Resource": "*"}
                        ],
                    },
                },
            },
            "User": {
                "Type": "AWS::IAM::User",
                "UpdateReplacePolicy": "Retain",
                "Properties": props,
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
    ), f"a UserName change must replace to {new!r} and skip deleting {old!r}: {rows!r}"
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


def _retire_user(iam, name: str) -> None:
    """Teardown for the retained user: drop its login profile, then the user itself."""
    try:
        iam.delete_login_profile(UserName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_user(UserName=name)
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
