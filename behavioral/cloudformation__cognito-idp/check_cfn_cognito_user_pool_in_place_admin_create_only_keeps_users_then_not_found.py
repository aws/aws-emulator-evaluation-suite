"""cfn-cognito-user-pool-in-place-admin-create-only-keeps-users-then-not-found."""

from __future__ import annotations

import base64
import json
import re
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-cognito-user-pool-in-place-admin-create-only-keeps-users-then-not-found"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-idp"]

#: A stack transition takes seconds to minutes; the cap only stops a hung poll.
_STACK_CAP_S = 600.0
_GONE_CAP_S = 120.0
_POLL_S = 2.0

_TAGS = [{"Key": "sim2real", "Value": CHECK}]
_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

#: Cognito's refusal of SignUp once only administrators may create users.
_SIGNUP_REFUSED = ("NotAuthorizedException", "SignUp is not permitted for this user pool")
#: Cognito's refusal of a user pool that no longer exists.
_NOT_FOUND_CODE = "ResourceNotFoundException"
_NOT_FOUND_MESSAGE = "User pool {pool_id} does not exist."


def _template(pool_name: str, client_name: str, admin_only: bool) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Pool": {
                    "Type": "AWS::Cognito::UserPool",
                    "Properties": {
                        "UserPoolName": pool_name,
                        "DeletionProtection": "INACTIVE",
                        "AdminCreateUserConfig": {"AllowAdminCreateUserOnly": admin_only},
                        "UserPoolTags": {"sim2real": CHECK},
                    },
                },
                "Client": {
                    "Type": "AWS::Cognito::UserPoolClient",
                    "Properties": {
                        "UserPoolId": {"Ref": "Pool"},
                        "ClientName": client_name,
                        "GenerateSecret": False,
                        "ExplicitAuthFlows": _FLOWS,
                    },
                },
            },
            "Outputs": {
                "PoolId": {"Value": {"Ref": "Pool"}},
                "ClientId": {"Value": {"Ref": "Client"}},
            },
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
    """A CloudFormation user pool signs users up and in; AllowAdminCreateUserOnly updates in place.

    The update refuses SignUp but keeps the pool and its users; no UserPool property forces a
    replacement, so there is no Retain step; delete: DescribeUserPool ResourceNotFoundException.

    Reference:
    https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html
    """
    cfn = ctx.client("cloudformation")
    idp = ctx.client("cognito-idp")
    pool_name = ctx.unique_name("sim2real-cfnpool-")
    client_name = ctx.unique_name("sim2real-cfnpool-client-")
    stack_name = ctx.unique_name("sim2real-cfnpool-stack-")
    admin_user = ctx.unique_name("sim2real-admin-")
    self_user = ctx.unique_name("sim2real-self-")
    password = _password()
    ref = {"stack": stack_name}

    ctx.on_cleanup(lambda: _teardown_stack(cfn, ref))

    # ---- 1. create: CloudFormation's view, Cognito's view, sign-up and admin sign-in
    ref["stack"] = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(pool_name, client_name, False),
        Tags=_TAGS,
    )["StackId"]
    stack = _settle(ctx, cfn, ref["stack"])
    _expect(cfn, stack, "CREATE_COMPLETE")
    ids = _physical_ids(cfn, ref["stack"])
    pool_id, client_id = ids["Pool"], ids["Client"]
    refs = _outputs(stack)
    assert refs == {"PoolId": pool_id, "ClientId": client_id}, (
        f"Ref must return each physical id: outputs {refs!r}, resources {ids!r}"
    )
    assert re.fullmatch(rf"{re.escape(ctx.region)}_[0-9a-zA-Z]+", pool_id), (
        f"a user pool's physical id is its <region>_<suffix> pool id, not {pool_id!r}"
    )
    _assert_pool(idp, pool_id, pool_name, False)
    signed_up = idp.sign_up(ClientId=client_id, Username=self_user, Password=password)
    assert signed_up.get("UserConfirmed") is False, f"SignUp answered {signed_up!r}"
    idp.admin_create_user(UserPoolId=pool_id, Username=admin_user, MessageAction="SUPPRESS")
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=admin_user, Password=password, Permanent=True
    )
    _assert_sign_in(idp, pool_id, client_id, admin_user, password)

    # ---- 2. in-place: AllowAdminCreateUserOnly on the same pool refuses SignUp
    events = _update(ctx, cfn, ref, _template(pool_name, client_name, True))
    assert _physical_ids(cfn, ref["stack"]) == ids, "an in-place update keeps pool and client"
    _assert_in_place(_rows(events, set(), "Pool"), pool_id, "Pool")
    _assert_pool(idp, pool_id, pool_name, True)
    # Each attempt signs up a fresh user, so a sign-up that lands before the setting does is
    # never answered UsernameExistsException by the next attempt.
    got = _poll(
        ctx,
        lambda: _signup_outcome(idp, client_id, ctx.unique_name("sim2real-late-"), password),
        lambda outcome: outcome[0] == _SIGNUP_REFUSED[0],
        "SignUp refused after the update",
    )
    assert got == _SIGNUP_REFUSED, f"SignUp after the update answered {got!r}"
    # The pool kept its users: the admin user signs in, the self-signed user is still pending.
    _assert_sign_in(idp, pool_id, client_id, admin_user, password)
    status = idp.admin_get_user(UserPoolId=pool_id, Username=self_user).get("UserStatus")
    assert status == "UNCONFIRMED", f"the signed-up user must survive in place: {status!r}"

    # ---- 3. delete: Cognito no longer knows the stack's pool
    _delete_stack(ctx, cfn, ref["stack"])
    got = _wait_error(
        ctx, lambda: idp.describe_user_pool(UserPoolId=pool_id), _NOT_FOUND_CODE, pool_id
    )
    want = (_NOT_FOUND_CODE, _NOT_FOUND_MESSAGE.format(pool_id=pool_id))
    assert got == want, f"DescribeUserPool after the stack delete answered {got!r}, not {want!r}"


def _password() -> str:
    """A password meeting the default policy: upper, lower, digit, symbol, over 8 characters."""
    return "Aa1!" + secrets.token_hex(8)


def _assert_pool(idp, pool_id: str, name: str, admin_only: bool) -> None:
    """DescribeUserPool reports the template's name, sign-up setting and protection exactly."""
    pool = idp.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    got = {
        "Id": pool.get("Id"),
        "Name": pool.get("Name"),
        "AllowAdminCreateUserOnly": pool.get("AdminCreateUserConfig", {}).get(
            "AllowAdminCreateUserOnly"
        ),
        "DeletionProtection": pool.get("DeletionProtection"),
        "sim2real tag": pool.get("UserPoolTags", {}).get("sim2real"),
    }
    want = {
        "Id": pool_id,
        "Name": name,
        "AllowAdminCreateUserOnly": admin_only,
        "DeletionProtection": "INACTIVE",
        "sim2real tag": CHECK,
    }
    assert got == want, f"DescribeUserPool {pool_id}: {got!r}, expected {want!r}"


def _signup_outcome(idp, client_id: str, username: str, password: str):
    """("signed-up", None) when SignUp succeeds, else the (code, message) it is refused with."""
    try:
        idp.sign_up(ClientId=client_id, Username=username, Password=password)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return "signed-up", None


def _assert_sign_in(idp, pool_id: str, client_id: str, username: str, password: str) -> None:
    """ADMIN_USER_PASSWORD_AUTH returns an access token issued to this user by this client."""
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    claims = _claims(auth["AuthenticationResult"]["AccessToken"])
    got = {k: claims.get(k) for k in ("username", "client_id", "token_use")}
    want = {"username": username, "client_id": client_id, "token_use": "access"}
    assert got == want, f"access token claims {got!r}, expected {want!r}"


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
