"""cfn-cognito-role-attachment-in-place-role-swap-retained-pool-move-then-not-found."""

from __future__ import annotations

import json
import time

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-cognito-role-attachment-in-place-role-swap-retained-pool-move-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-identity", "sts"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
#: A new role, trust policy or role mapping takes seconds to become usable.
_PROPAGATE_CAP_S = 90.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_POOLS = ("PoolA", "PoolB")
_ROLES = ("RoleA", "RoleB")
#: The role session name Cognito Identity gives the credentials it vends.
_SESSION = "CognitoIdentityCredentials"
#: Both pools' developer provider: only identities this check's caller issues are authenticated,
#: and no pool admits unauthenticated identities.
_DEVELOPER = "login.cfnreality.attach"
_TOKEN_LOGIN = "cognito-identity.amazonaws.com"

#: Cognito Identity's refusal of an identity pool that no longer exists.
_NOT_FOUND_CODE = "ResourceNotFoundException"
_NOT_FOUND_MESSAGE = "IdentityPool '{pool_id}' not found."


def _template(names: dict[str, str], pool: str, role: str) -> str:
    """Two developer-authenticated identity pools, two roles both trust, one attachment.

    The attachment gives *pool* the authenticated *role*.
    """
    resources: dict = {}
    for logical in _POOLS:
        resources[logical] = {
            "Type": "AWS::Cognito::IdentityPool",
            "Properties": {
                "IdentityPoolName": names[logical],
                "AllowUnauthenticatedIdentities": False,
                "AllowClassicFlow": False,
                "DeveloperProviderName": _DEVELOPER,
                "IdentityPoolTags": _TAGS,
            },
        }
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "cognito-identity.amazonaws.com:aud": [{"Ref": p} for p in _POOLS]
                    },
                    "ForAnyValue:StringLike": {
                        "cognito-identity.amazonaws.com:amr": "authenticated"
                    },
                },
            }
        ],
    }
    for logical in _ROLES:
        # No permissions policy: the vended credentials only identify themselves.
        resources[logical] = {
            "Type": "AWS::IAM::Role",
            "Properties": {"AssumeRolePolicyDocument": trust, "Tags": _TAGS},
        }
    resources["Attachment"] = {
        "Type": "AWS::Cognito::IdentityPoolRoleAttachment",
        # IdentityPoolId is create-only, so moving the attachment replaces it.
        "UpdateReplacePolicy": "Retain",
        "Properties": {
            "IdentityPoolId": {"Ref": pool},
            "Roles": {"authenticated": {"Fn::GetAtt": [role, "Arn"]}},
        },
    }
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": resources,
            "Outputs": {"AttachedPool": {"Value": {"Ref": "Attachment"}}},
        }
    )


@tags(
    "axis:happy-path",
    "cap:c3",
    "concern:deploy",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation role attachment makes its pool vend authenticated sessions of its role.

    A role swap updates it in place; an IdentityPoolId change under UpdateReplacePolicy Retain
    attaches the other pool and keeps the old pool's roles; delete: ResourceNotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-identitypoolroleattachment.html
    """
    cfn = ctx.client("cloudformation")
    identity = ctx.client("cognito-identity")
    partition = ctx.client("sts").get_caller_identity()["Arn"].split(":")[1]
    names = {p: ctx.unique_name(f"sim2real_cfnattach_{p.lower()}_") for p in _POOLS}
    user_a = ctx.unique_name("sim2real-dev-user-a-")
    user_b = ctx.unique_name("sim2real-dev-user-b-")
    stack_name = ctx.unique_name("sim2real-cfnattach-stack-")
    ref = {"stack": stack_name}

    # The retained attachment is pool A's role setting; the stack delete removes pool A.
    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view, Cognito Identity's view, credentials of role A
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(names, "PoolA", "RoleA"),
        Capabilities=["CAPABILITY_IAM"],
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    pool_a, pool_b, old_attachment = ids["PoolA"], ids["PoolB"], ids["Attachment"]
    arn = {r: f"arn:{partition}:iam::{ctx.account}:role/{ids[r]}" for r in _ROLES}
    assert _outputs(stack) == {"AttachedPool": pool_a}, f"Ref must return pool A {pool_a!r}"
    _assert_roles(identity, pool_a, arn["RoleA"])
    _assert_vends(ctx, identity, pool_a, user_a, partition, ids["RoleA"])

    # ---- 2. in-place: the attachment gives pool A role B instead
    events = _update(
        ctx, cfn, ref, _template(names, "PoolA", "RoleB"), Capabilities=["CAPABILITY_IAM"]
    )
    assert _physical_ids(cfn, ref["stack"]) == ids, "an in-place update keeps every physical id"
    _assert_in_place(_rows(events, set(), "Attachment"), old_attachment, "Attachment")
    _assert_roles(identity, pool_a, arn["RoleB"])
    _assert_vends(ctx, identity, pool_a, user_a, partition, ids["RoleB"])

    # ---- 3. replacement under UpdateReplacePolicy Retain: pool B attached, pool A's roles kept
    events = _update(
        ctx, cfn, ref, _template(names, "PoolB", "RoleB"), Capabilities=["CAPABILITY_IAM"]
    )
    new_attachment = _physical_ids(cfn, ref["stack"])["Attachment"]
    assert new_attachment != old_attachment, "an IdentityPoolId change replaces the attachment"
    assert _outputs(_settle(ctx, cfn, ref["stack"])) == {"AttachedPool": pool_b}, (
        f"Ref must return pool B {pool_b!r}"
    )
    rows = _rows(events, set(), "Attachment")
    _assert_replaced_and_retained(rows, old_attachment, new_attachment, "Attachment")
    _assert_roles(identity, pool_b, arn["RoleB"])
    _assert_vends(ctx, identity, pool_b, user_b, partition, ids["RoleB"])
    _assert_roles(identity, pool_a, arn["RoleB"])
    _assert_vends(ctx, identity, pool_a, user_a, partition, ids["RoleB"])

    # ---- 4. delete: Cognito Identity no longer knows the attached pool
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: identity.get_identity_pool_roles(IdentityPoolId=pool_b),
        _NOT_FOUND_CODE,
        f"identity pool {pool_b}",
    )
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(pool_id=pool_b))
    assert got == want, f"GetIdentityPoolRoles after the delete answered {got!r}, not {want!r}"


def _assert_roles(identity, pool_id: str, role_arn: str) -> None:
    """GetIdentityPoolRoles reports exactly the attached authenticated role."""
    resp = identity.get_identity_pool_roles(IdentityPoolId=pool_id)
    got = (resp.get("IdentityPoolId"), resp.get("Roles"), resp.get("RoleMappings"))
    want = (pool_id, {"authenticated": role_arn}, None)
    assert got == want, f"GetIdentityPoolRoles {pool_id}: {got!r}, expected {want!r}"


def _assert_vends(ctx, identity, pool_id: str, user: str, partition: str, role_name: str) -> None:
    """A developer identity's OpenID token buys a session of *role_name*, as STS reports it.

    A new role or role setting propagates in seconds, so the vend is retried until it holds.
    Neither the token nor the credentials ever reach a message.
    """
    want = f"arn:{partition}:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION}"
    attempts = {"n": 0}

    def caller():
        attempts["n"] += 1
        issued = identity.get_open_id_token_for_developer_identity(
            IdentityPoolId=pool_id, Logins={_DEVELOPER: user}
        )
        try:
            creds = identity.get_credentials_for_identity(
                IdentityId=issued["IdentityId"], Logins={_TOKEN_LOGIN: issued["Token"]}
            )["Credentials"]
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        sts = ctx.client(
            "sts",
            config=Config(user_agent_extra=f"sim2real-attempt-{attempts['n']}"),
            creds={
                "aws_access_key_id": creds["AccessKeyId"],
                "aws_secret_access_key": creds["SecretKey"],
                "aws_session_token": creds["SessionToken"],
            },
        )
        return sts.get_caller_identity()["Arn"]

    got = _poll(
        ctx,
        caller,
        lambda arn: arn == want,
        f"{user} in {pool_id} vending {role_name}",
        _PROPAGATE_CAP_S,
    )
    assert got == want, f"the vended credentials are {got!r}, expected {want!r}"


# ===== helpers =====


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s.

    The wait then fails with its own message. A teardown passes ctx=None
    and waits the full cap; in a teardown, ctx.time_left() counts down the runner's cleanup timeout.
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


def _teardown_stack(cfn, ref: dict) -> None:
    """Teardown by the StackId once known, else by name; a stack that never existed is done.

    Its waits use fixed caps (ctx=None), never the run's remaining time.
    """
    try:
        stack = cfn.describe_stacks(StackName=ref["stack"])["Stacks"][0]
    except ClientError as exc:
        if exc.response["Error"]["Message"] == f"Stack with id {ref['stack']} does not exist":
            return
        raise
    if stack["StackStatus"] == "DELETE_COMPLETE":
        return
    if stack["StackStatus"].endswith("_IN_PROGRESS"):
        stack = _settle(None, cfn, stack["StackId"])
    _delete_stack(None, cfn, stack["StackId"])


def _poll(ctx, probe, done, what: str, cap_s: float = 60.0):
    """Call probe() until done(result) holds and return it; an eventually consistent read."""
    timeout = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout
    while True:
        last = probe()
        if done(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while waiting for {what}")
            raise AssertionError(f"{what} not reached after {timeout:.0f}s; last {last!r}")
        time.sleep(_POLL_S)


def _update(ctx, cfn, ref: dict, body: str, **kwargs) -> list[dict]:
    """UpdateStack to *body*, require UPDATE_COMPLETE, and return the events it added."""
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=body, Tags=_TAGS, **kwargs)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    return [e for e in _events(cfn, ref["stack"]) if e["EventId"] not in seen]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
