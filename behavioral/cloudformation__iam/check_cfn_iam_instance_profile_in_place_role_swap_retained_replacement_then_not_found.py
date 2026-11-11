"""cfn-iam-instance-profile-in-place-role-swap-retained-replacement-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-instance-profile-in-place-role-swap-retained-replacement-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: IAM is eventually consistent, so a read after a write can lag for a short while.
_CONVERGE_CAP_S = 60.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_PATH = "/sim2real/"

#: IAM's refusal of an instance profile that no longer exists.
_NOT_FOUND_CODE = "NoSuchEntity"
_NOT_FOUND_MESSAGE = "Instance Profile {name} cannot be found."


def _role() -> dict:
    return {
        "Type": "AWS::IAM::Role",
        "Properties": {
            "Path": _PATH,
            "AssumeRolePolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            },
            "Tags": _TAGS,
        },
    }


def _template(profile_name: str, role: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "RoleA": _role(),
                "RoleB": _role(),
                "Profile": {
                    "Type": "AWS::IAM::InstanceProfile",
                    # InstanceProfileName is create-only, so renaming replaces the profile.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "InstanceProfileName": profile_name,
                        "Path": _PATH,
                        "Roles": [{"Ref": role}],
                    },
                },
            },
            "Outputs": {
                "ProfileArn": {"Value": {"Fn::GetAtt": ["Profile", "Arn"]}},
                "RoleAArn": {"Value": {"Fn::GetAtt": ["RoleA", "Arn"]}},
                "RoleBArn": {"Value": {"Fn::GetAtt": ["RoleB", "Arn"]}},
            },
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation instance profile reads back with its role and survives replacement.

    A Roles change swaps the role in place; an InstanceProfileName change under
    UpdateReplacePolicy Retain keeps the old profile with its role; delete: NoSuchEntity.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-instanceprofile.html
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    first = ctx.unique_name("sim2real-cfnip-a-")
    second = ctx.unique_name("sim2real-cfnip-b-")
    stack_name = ctx.unique_name("sim2real-cfnip-stack-")
    ref = {"stack": stack_name}
    retained = {}

    # The replaced profile is retained and holds a stack role, which IAM deletes only once no
    # profile holds it; the retained profile goes first.
    ctx.on_cleanup(lambda: _teardown_stack(None, cfn, ref))
    ctx.on_cleanup(lambda: _delete_profile(iam, retained.get("name")))

    # ---- 1. create: CloudFormation's view and IAM's view of the profile and its role
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(first, "RoleA"),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    out = _outputs(stack)
    ids = _physical_ids(cfn, ref["stack"])
    role_a, role_b = ids["RoleA"], ids["RoleB"]
    roles = {role_a: out["RoleAArn"], role_b: out["RoleBArn"]}
    # The partition comes from an ARN the stack published.
    prefix = ":".join(out["RoleAArn"].split(":")[:5])
    first_arn = f"{prefix}:instance-profile{_PATH}{first}"
    assert ids["Profile"] == first, f"the profile's physical id must be its name {first!r}"
    assert out["ProfileArn"] == first_arn, (
        f"GetAtt Profile.Arn {out['ProfileArn']!r}, expected {first_arn!r}"
    )
    _assert_profile(ctx, iam, first, first_arn, role_a, roles)
    _assert_held_by(ctx, iam, {role_a: [first], role_b: []})

    # ---- 2. in-place: the profile now holds role B, the same profile
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(first, "RoleB"),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=_TAGS,
    )
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    assert _physical_ids(cfn, ref["stack"])["Profile"] == first, "an in-place update keeps it"
    _assert_in_place(_rows(_events(cfn, ref["stack"]), seen, "Profile"), first, "Profile")
    _assert_profile(ctx, iam, first, first_arn, role_b, roles)
    _assert_held_by(ctx, iam, {role_a: [], role_b: [first]})

    # ---- 3. replacement under UpdateReplacePolicy Retain: a new profile, the old one kept
    # Recorded first, so a failed or unfinished replacement still releases role B in teardown.
    retained["name"] = first
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(
        StackName=ref["stack"],
        TemplateBody=_template(second, "RoleB"),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=_TAGS,
    )
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "UPDATE_COMPLETE")
    second_arn = f"{prefix}:instance-profile{_PATH}{second}"
    assert _physical_ids(cfn, ref["stack"])["Profile"] == second, (
        f"the stack must track the replacement {second!r}"
    )
    assert _outputs(stack)["ProfileArn"] == second_arn, f"GetAtt Profile.Arn {stack!r}"
    _assert_replaced_and_retained(
        _rows(_events(cfn, ref["stack"]), seen, "Profile"), first, second, "Profile"
    )
    _assert_profile(ctx, iam, second, second_arn, role_b, roles)
    _assert_profile(ctx, iam, first, first_arn, role_b, roles)
    _assert_held_by(ctx, iam, {role_a: [], role_b: sorted([first, second])})

    # ---- 4. delete: IAM no longer knows the stack's profile
    # The retained profile is no longer the stack's; releasing it lets the stack delete role B.
    _delete_profile(iam, first)
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: iam.get_instance_profile(InstanceProfileName=second),
        _NOT_FOUND_CODE,
        f"instance profile {second}",
    )
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(name=second))
    assert got == want, f"GetInstanceProfile after the stack delete answered {got!r}, want {want!r}"


def _assert_profile(ctx, iam, name: str, arn: str, role: str, roles: dict) -> None:
    """GetInstanceProfile reports the template's profile holding exactly *role*."""

    def read():
        p = iam.get_instance_profile(InstanceProfileName=name)["InstanceProfile"]
        return {
            "InstanceProfileName": p.get("InstanceProfileName"),
            "Path": p.get("Path"),
            "Arn": p.get("Arn"),
            "Roles": [(r.get("RoleName"), r.get("Arn"), r.get("Path")) for r in p.get("Roles", [])],
        }

    want = {
        "InstanceProfileName": name,
        "Path": _PATH,
        "Arn": arn,
        "Roles": [(role, roles[role], _PATH)],
    }
    got = _poll(
        ctx, read, lambda v: v == want, f"instance profile {name} holding {role}", _CONVERGE_CAP_S
    )
    assert got == want, f"GetInstanceProfile {name}: {got!r}, expected {want!r}"


def _assert_held_by(ctx, iam, want: dict[str, list[str]]) -> None:
    """ListInstanceProfilesForRole names exactly the profiles that hold each role."""

    def read():
        return {
            role: sorted(
                p["InstanceProfileName"]
                for p in iam.list_instance_profiles_for_role(RoleName=role)["InstanceProfiles"]
            )
            for role in want
        }

    got = _poll(ctx, read, lambda v: v == want, "the profiles holding each role", _CONVERGE_CAP_S)
    assert got == want, f"ListInstanceProfilesForRole: {got!r}, expected {want!r}"


def _delete_profile(iam, name: str | None) -> None:
    """Remove the profile's roles and delete it; a profile already gone is done."""
    if name is None:
        return
    try:
        profile = iam.get_instance_profile(InstanceProfileName=name)["InstanceProfile"]
        for role in profile.get("Roles", []):
            iam.remove_role_from_instance_profile(
                InstanceProfileName=name, RoleName=role["RoleName"]
            )
        iam.delete_instance_profile(InstanceProfileName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != _NOT_FOUND_CODE:
            raise


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. A teardown passes ``ctx=None`` and waits the full
    cap_s; in a teardown, ctx.time_left() counts down the runner's cleanup timeout.
    """
    left = None if ctx is None else ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = None if ctx is None else ctx.time_left()
    return left is not None and left <= 6.0


def _settle(ctx, cfn, stack_id: str) -> dict:
    """Poll DescribeStacks by StackId until the stack leaves every *_IN_PROGRESS status."""
    timeout = _budget_s(ctx, _STACK_CAP_S)
    deadline = time.monotonic() + timeout
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {stack_id} was {stack['StackStatus']}")
            raise AssertionError(
                f"stack {stack_id} still {stack['StackStatus']!r} after {timeout:.0f}s"
            )
        time.sleep(_POLL_S)


def _expect(cfn, stack: dict, want: str) -> None:
    """The settled stack is in status *want*; otherwise name every failed resource event."""
    if stack["StackStatus"] == want:
        return
    failed = [
        (e["LogicalResourceId"], e["ResourceStatus"], e.get("ResourceStatusReason"))
        for e in _events(cfn, stack["StackId"])
        if e["ResourceStatus"].endswith("_FAILED")
    ]
    raise AssertionError(
        f"stack ended {stack['StackStatus']!r} ({stack.get('StackStatusReason')!r}), expected "
        f"{want!r}; failed events: {failed!r}"
    )


def _events(cfn, stack_id: str) -> list[dict]:
    """Every stack event, oldest first."""
    events: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        events.extend(page["StackEvents"])
    return list(reversed(events))


def _rows(events: list[dict], seen: set[str], logical_id: str) -> list[tuple]:
    """(status, reason, physical id) of *logical_id*'s events not in *seen*, oldest first."""
    return [
        (e["ResourceStatus"], e.get("ResourceStatusReason"), e.get("PhysicalResourceId"))
        for e in events
        if e["EventId"] not in seen and e["LogicalResourceId"] == logical_id
    ]


def _assert_in_place(rows: list[tuple], physical_id: str, logical_id: str) -> None:
    """The resource's update events are exactly an in-place update ending on *physical_id*."""
    statuses = [status for status, _, _ in rows]
    assert statuses == ["UPDATE_IN_PROGRESS", "UPDATE_COMPLETE"], (
        f"{logical_id} must update in place with no replacement, its events were {rows!r}"
    )
    assert rows[-1][2] == physical_id, (
        f"{logical_id} must complete its update on {physical_id!r}, its events were {rows!r}"
    )


def _assert_replaced_and_retained(rows: list[tuple], old_id: str, new_id: str, logical_id: str):
    """The resource's events replace *old_id* with *new_id* and skip deleting *old_id*."""
    statuses = [(status, reason) for status, reason, _ in rows]
    assert (
        "UPDATE_IN_PROGRESS",
        "Requested update requires the creation of a new physical resource; hence creating one.",
    ) in statuses, f"{logical_id} must announce its replacement, its events were {rows!r}"
    assert ("UPDATE_COMPLETE", new_id) in [(s, pid) for s, _, pid in rows], (
        f"{logical_id} must complete as the new physical id {new_id!r}, its events were {rows!r}"
    )
    old_rows = [(status, pid) for status, _, pid in rows if status.startswith("DELETE_")]
    assert old_rows == [("DELETE_SKIPPED", old_id)], (
        f"UpdateReplacePolicy Retain must skip deleting the replaced {old_id!r}, the delete events "
        f"of {logical_id} were {old_rows!r}"
    )


def _physical_ids(cfn, stack_id: str) -> dict[str, str]:
    """Logical id -> physical id of every resource in the stack."""
    return {
        r["LogicalResourceId"]: r["PhysicalResourceId"]
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    }


def _outputs(stack: dict) -> dict[str, str]:
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _wait_error(ctx, fn, code: str, what: str):
    """Poll ``fn`` until it raises *code* (a delete can lag DELETE_COMPLETE); (code, message)."""
    timeout = _budget_s(ctx, _GONE_CAP_S)
    deadline = time.monotonic() + timeout
    last = "never read"
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            if err.get("Code") == code:
                return err.get("Code"), err.get("Message")
            raise
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while {what} still answered")
            raise AssertionError(f"{what} still answered after {timeout:.0f}s: {last!r}")
        time.sleep(_POLL_S)


def _delete_stack(ctx, cfn, stack_id: str) -> None:
    """Delete the stack by StackId and wait for DELETE_COMPLETE; raises on any other end."""
    cfn.delete_stack(StackName=stack_id)
    _expect(cfn, _settle(ctx, cfn, stack_id), "DELETE_COMPLETE")


def _teardown_stack(ctx, cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done."""
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(ctx, cfn, stack["StackId"])
    _delete_stack(ctx, cfn, stack["StackId"])


def _poll(ctx, read, ok, what: str, cap_s: float):
    """Re-read until ``ok(value)`` holds, for an eventually consistent read; the last value."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        value = read()
        if ok(value):
            return value
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while waiting for {what}")
            raise AssertionError(f"{what} not reached after {timeout:.0f}s; last read {value!r}")
        time.sleep(_POLL_S)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
