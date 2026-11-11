"""cfn-cognito-identity-pool-in-place-rename-keeps-developer-identities-then-not-found."""

from __future__ import annotations

import base64
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-cognito-identity-pool-in-place-rename-keeps-developer-identities-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-identity"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
#: The pool's developer provider: identities are issued to back-end users, never anonymously.
_DEVELOPER = "login.cfnreality.check"

#: Cognito Identity's refusal of an identity pool that no longer exists.
_NOT_FOUND_CODE = "ResourceNotFoundException"
_NOT_FOUND_MESSAGE = "IdentityPool '{pool_id}' not found."


def _template(pool_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Pool": {
                    "Type": "AWS::Cognito::IdentityPool",
                    "Properties": {
                        "IdentityPoolName": pool_name,
                        "AllowUnauthenticatedIdentities": False,
                        "AllowClassicFlow": False,
                        "DeveloperProviderName": _DEVELOPER,
                        "IdentityPoolTags": _TAGS,
                    },
                }
            },
            "Outputs": {"PoolId": {"Value": {"Ref": "Pool"}}},
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
    """A CloudFormation identity pool issues developer identities and OpenID tokens for itself.

    A rename updates it in place and keeps its identities; no IdentityPool property forces a
    replacement, so there is no Retain step; delete: DescribeIdentityPool ResourceNotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-identitypool.html
    """
    cfn = ctx.client("cloudformation")
    identity = ctx.client("cognito-identity")
    first_name = ctx.unique_name("sim2real_cfnidp_first_")
    second_name = ctx.unique_name("sim2real_cfnidp_second_")
    stack_name = ctx.unique_name("sim2real-cfnidp-stack-")
    developer_user = ctx.unique_name("sim2real-dev-user-")
    ref = {"stack": stack_name}

    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view, Cognito Identity's view, a developer identity
    ref["stack"] = cfn.create_stack(
        StackName=stack_name, TemplateBody=_template(first_name), Tags=_TAGS
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    pool_id = _physical_ids(cfn, ref["stack"])["Pool"]
    assert _outputs(stack) == {"PoolId": pool_id}, f"Ref must return the pool id {pool_id!r}"
    assert re.fullmatch(rf"{re.escape(ctx.region)}:[0-9a-f-]{{36}}", pool_id), (
        f"an identity pool's physical id is its <region>:<uuid> pool id, not {pool_id!r}"
    )
    _assert_pool(identity, pool_id, first_name)
    identity_id = _assert_developer_identity(identity, pool_id, developer_user, None)
    looked_up = identity.lookup_developer_identity(
        IdentityPoolId=pool_id, DeveloperUserIdentifier=developer_user, MaxResults=1
    ).get("IdentityId")
    assert looked_up == identity_id, f"LookupDeveloperIdentity answered {looked_up!r}"

    # ---- 2. in-place: a new IdentityPoolName on the same pool, the identity kept
    events = _update(ctx, cfn, ref, _template(second_name))
    assert _physical_ids(cfn, ref["stack"])["Pool"] == pool_id, "a rename keeps the pool"
    _assert_in_place(_rows(events, set(), "Pool"), pool_id, "Pool")
    _assert_pool(identity, pool_id, second_name)
    _assert_developer_identity(identity, pool_id, developer_user, identity_id)

    # ---- 3. delete: Cognito Identity no longer knows the stack's pool
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx,
        lambda: identity.describe_identity_pool(IdentityPoolId=pool_id),
        _NOT_FOUND_CODE,
        f"identity pool {pool_id}",
    )
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(pool_id=pool_id))
    assert got == want, f"DescribeIdentityPool after the delete answered {got!r}, not {want!r}"


def _assert_pool(identity, pool_id: str, name: str) -> None:
    """DescribeIdentityPool reports the template's name, flows, provider and tag exactly."""
    pool = identity.describe_identity_pool(IdentityPoolId=pool_id)
    got = {
        "IdentityPoolId": pool.get("IdentityPoolId"),
        "IdentityPoolName": pool.get("IdentityPoolName"),
        "AllowUnauthenticatedIdentities": pool.get("AllowUnauthenticatedIdentities"),
        "AllowClassicFlow": pool.get("AllowClassicFlow"),
        "DeveloperProviderName": pool.get("DeveloperProviderName"),
        "sim2real tag": pool.get("IdentityPoolTags", {}).get("sim2real"),
    }
    want = {
        "IdentityPoolId": pool_id,
        "IdentityPoolName": name,
        "AllowUnauthenticatedIdentities": False,
        "AllowClassicFlow": False,
        "DeveloperProviderName": _DEVELOPER,
        "sim2real tag": CHECK,
    }
    assert got == want, f"DescribeIdentityPool {pool_id}: {got!r}, expected {want!r}"


def _assert_developer_identity(identity, pool_id: str, user: str, known: str | None) -> str:
    """GetOpenIdTokenForDeveloperIdentity issues the user's identity and a token for this pool."""
    resp = identity.get_open_id_token_for_developer_identity(
        IdentityPoolId=pool_id, Logins={_DEVELOPER: user}
    )
    identity_id = resp.get("IdentityId") or ""
    if known is not None:
        assert identity_id == known, (
            f"the pool must keep {user}'s identity {known!r}, got {identity_id!r}"
        )
    assert identity_id.startswith(f"{pool_id.split(':')[0]}:"), f"IdentityId {identity_id!r}"
    claims = _claims(resp.get("Token") or "")
    got = (claims.get("aud"), claims.get("sub"))
    assert got == (pool_id, identity_id), (
        f"the OpenID token names (aud, sub) {got!r}, expected ({pool_id!r}, {identity_id!r})"
    )
    return identity_id


def _claims(token: str) -> dict:
    """The payload of a JWT, decoded without verifying its signature."""
    payload = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))


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


def _update(ctx, cfn, ref: dict, body: str, **kwargs) -> list[dict]:
    """UpdateStack to *body*, require UPDATE_COMPLETE, and return the events it added."""
    seen = {e["EventId"] for e in _events(cfn, ref["stack"])}
    cfn.update_stack(StackName=ref["stack"], TemplateBody=body, Tags=_TAGS, **kwargs)
    _expect(cfn, _settle(ctx, cfn, ref["stack"]), "UPDATE_COMPLETE")
    return [e for e in _events(cfn, ref["stack"]) if e["EventId"] not in seen]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
