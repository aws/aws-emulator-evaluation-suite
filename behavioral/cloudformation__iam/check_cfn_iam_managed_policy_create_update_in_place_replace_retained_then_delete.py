"""cfn-iam-managed-policy-create-update-in-place-replace-retained-then-delete."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-managed-policy-create-update-in-place-replace-retained-then-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam"]

#: A stack operation takes seconds to a few minutes; the bound only stops a hung poll.
_STACK_S = 600.0
#: An attachment reaches the policy simulator within seconds; the bound only stops a hung poll.
_SIMULATE_S = 60.0
#: A change or delete reaches every read within seconds; the bound only stops a hung poll.
_PROPAGATE_S = 60.0
_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_NAMED_IAM = ["CAPABILITY_NAMED_IAM"]
_REPLACING = (
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
    """An AWS::IAM::ManagedPolicy survives create, in-place update, retained replacement and delete.

    IAM reads back each document and the simulator grants exactly it to the attached role; a new
    document is version v2 of the same ARN; a ManagedPolicyName change under Retain keeps the old.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iam-managedpolicy.html
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")

    stack_name = ctx.unique_name("sim2real-cfnreal-mpol-")
    role_name = ctx.unique_name("sim2real-cfnreal-mpol-role-")
    policy_v1 = ctx.unique_name("sim2real-cfnreal-mpol-a-")
    policy_v2 = ctx.unique_name("sim2real-cfnreal-mpol-b-")
    read_doc = _document("s3:GetObject")
    write_doc = _document("s3:PutObject")

    # The role the policy attaches to is the check's own; the replaced policy outlives the stack.
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_trust(ctx.account)),
        Tags=_TAGS,
    )["Role"]["Arn"]
    partition = role_arn.split(":")[1]
    arn_v1 = f"arn:{partition}:iam::{ctx.account}:policy/{policy_v1}"
    arn_v2 = f"arn:{partition}:iam::{ctx.account}:policy/{policy_v2}"
    ctx.on_cleanup(lambda: _delete_policy(iam, arn_v1))
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))

    # ---- 1. create: CloudFormation view, IAM view, behaviour --------------------------------
    stack_id = cfn.create_stack(
        StackName=stack_name,
        Capabilities=_NAMED_IAM,
        Tags=_TAGS,
        TemplateBody=_template(policy_v1, role_name, read_doc),
    )["StackId"]
    created = _settle(ctx, cfn, stack_id)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"create ended {created['StackStatus']!r}: {created.get('StackStatusReason')!r}"
    )
    _assert_tracks(cfn, stack_id, "Policy", arn_v1)
    _assert_policy(iam, arn_v1, policy_v1, "v1", read_doc)
    attached = iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    assert attached == [{"PolicyName": policy_v1, "PolicyArn": arn_v1}], (
        f"the policy must be attached to the templated role, got {attached!r}"
    )
    _assert_grants(ctx, iam, role_arn, {"s3:GetObject": "allowed", "s3:PutObject": "implicitDeny"})

    # ---- 2. in-place update of the mutable PolicyDocument -----------------------------------
    rows = _update(
        ctx,
        cfn,
        stack_id,
        "Policy",
        _template(policy_v1, role_name, write_doc),
        Capabilities=_NAMED_IAM,
    )
    _assert_updated_in_place(rows, arn_v1)
    _assert_tracks(cfn, stack_id, "Policy", arn_v1)
    _assert_policy(iam, arn_v1, policy_v1, "v2", write_doc)
    _assert_grants(ctx, iam, role_arn, {"s3:GetObject": "implicitDeny", "s3:PutObject": "allowed"})

    # ---- 3. ManagedPolicyName forces replacement; UpdateReplacePolicy Retain keeps the old --
    rows = _update(
        ctx,
        cfn,
        stack_id,
        "Policy",
        _template(policy_v2, role_name, write_doc),
        Capabilities=_NAMED_IAM,
    )
    _assert_replaced_and_retained(rows, arn_v1, arn_v2)
    _assert_tracks(cfn, stack_id, "Policy", arn_v2)
    _assert_policy(iam, arn_v2, policy_v2, "v1", write_doc)
    _assert_policy(iam, arn_v1, policy_v1, "v2", write_doc)
    attached = {
        p["PolicyArn"]
        for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
    }
    assert attached == {arn_v1, arn_v2}, (
        f"the replacement is attached and the retained policy stays attached, got {attached!r}"
    )

    # ---- 4. DeleteStack: the policy it owns is gone -----------------------------------------
    _delete_and_confirm(ctx, cfn, stack_id)
    want = ("NoSuchEntity", f"Policy {arn_v2} was not found.")
    _await_error(ctx, lambda: iam.get_policy(PolicyArn=arn_v2), want, "GetPolicy after DeleteStack")
    assert iam.get_policy(PolicyArn=arn_v1)["Policy"]["PolicyName"] == policy_v1, (
        "the retained policy survives DeleteStack"
    )


def _document(action: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": action, "Resource": "*"}],
    }


def _trust(account: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": account},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def _template(name: str, role: str, document: dict) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Policy": {
                    "Type": "AWS::IAM::ManagedPolicy",
                    # ManagedPolicyName is create-only, so a new name replaces the policy.
                    "UpdateReplacePolicy": "Retain",
                    "Properties": {
                        "ManagedPolicyName": name,
                        "Description": "reality check policy",
                        "PolicyDocument": document,
                        "Roles": [role],
                    },
                },
            },
        }
    )


def _assert_policy(iam, arn: str, name: str, version: str, document: dict) -> None:
    """IAM's view: the policy's name, description, default version and that version's document."""
    policy = iam.get_policy(PolicyArn=arn)["Policy"]
    got = (policy["PolicyName"], policy.get("Description"), policy["DefaultVersionId"])
    assert got == (name, "reality check policy", version), f"GetPolicy {arn}: {policy!r}"
    stored = iam.get_policy_version(PolicyArn=arn, VersionId=version)["PolicyVersion"]
    assert stored["Document"] == document, (
        f"policy {arn} version {version} must hold the templated document, got {stored!r}"
    )


def _decisions(iam, role_arn: str) -> dict:
    results = iam.simulate_principal_policy(PolicySourceArn=role_arn, ActionNames=_ACTIONS)
    return {r["EvalActionName"]: r["EvalDecision"] for r in results["EvaluationResults"]}


def _assert_grants(ctx, iam, role_arn: str, want: dict) -> None:
    """Behaviour: the simulator evaluates the role's attached policy to exactly want."""
    _poll(
        ctx,
        lambda: _decisions(iam, role_arn),
        lambda d: d == want,
        cap_s=_SIMULATE_S,
        what=f"the role's simulated decisions to become {want!r}",
    )


def _delete_policy(iam, arn: str) -> None:
    """Detach the policy everywhere, drop its non-default versions, then delete it."""
    try:
        entities = iam.list_entities_for_policy(PolicyArn=arn)
        for role in entities["PolicyRoles"]:
            iam.detach_role_policy(RoleName=role["RoleName"], PolicyArn=arn)
        for version in iam.list_policy_versions(PolicyArn=arn)["Versions"]:
            if not version["IsDefaultVersion"]:
                iam.delete_policy_version(PolicyArn=arn, VersionId=version["VersionId"])
        iam.delete_policy(PolicyArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(iam, name: str) -> None:
    """Detach whatever is still attached, then delete the role."""
    try:
        for policy in iam.list_attached_role_policies(RoleName=name)["AttachedPolicies"]:
            iam.detach_role_policy(RoleName=name, PolicyArn=policy["PolicyArn"])
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
