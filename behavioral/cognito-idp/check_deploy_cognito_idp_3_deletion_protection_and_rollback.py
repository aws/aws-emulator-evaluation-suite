"""deploy-cognito-idp-3-deletion-protection-and-rollback."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "deploy-cognito-idp-3-deletion-protection-and-rollback"
GROUP = "deploy-lifecycle"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real-Pass123!"
_TERMINAL_WAIT_S = 600


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """With DeletionProtection=ACTIVE, DeleteStack lands DELETE_FAILED with the pool live,
    UpdateStack is refused, and lifting protection lets the delete converge; an OAuth code-flow
    client without CallbackURLs fails at create and the rollback removes the pool."""
    cfn = ctx.client("cloudformation")
    idp = ctx.client("cognito-idp")

    # ---- Stack B first: its create + rollback is the slow leg, so let it run alongside A.
    name_b = ctx.unique_name("sim2real-cfn-oauthrb-")
    tpl_b = {
        "Resources": {
            "Pool": {"Type": "AWS::Cognito::UserPool", "Properties": {"UserPoolName": name_b}},
            "Client": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "ClientName": f"{name_b}-client",
                    "UserPoolId": {"Ref": "Pool"},
                    "GenerateSecret": False,
                    "AllowedOAuthFlowsUserPoolClient": True,
                    "AllowedOAuthFlows": ["code"],
                    "AllowedOAuthScopes": ["openid"],
                    "SupportedIdentityProviders": ["COGNITO"],
                    # The one broken thing: no CallbackURLs.
                },
            },
        },
    }
    stack_b = cfn.create_stack(StackName=name_b, TemplateBody=json.dumps(tpl_b))["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, idp, stack_b))

    # ---- Stack A: protected pool + client that can authenticate.
    name_a = ctx.unique_name("sim2real-cfn-delprot-")
    tpl_a = {
        "Resources": {
            "Pool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {"UserPoolName": name_a, "DeletionProtection": "ACTIVE"},
            },
            "Client": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "ClientName": f"{name_a}-client",
                    "UserPoolId": {"Ref": "Pool"},
                    "GenerateSecret": False,
                    "ExplicitAuthFlows": [
                        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
                        "ALLOW_REFRESH_TOKEN_AUTH",
                    ],
                },
            },
        },
        "Outputs": {
            "UserPoolId": {"Value": {"Ref": "Pool"}},
            "ClientId": {"Value": {"Ref": "Client"}},
        },
    }
    stack_a = cfn.create_stack(StackName=name_a, TemplateBody=json.dumps(tpl_a))["StackId"]
    # Teardown lifts protection out-of-band first, because a protected pool never deletes.
    ctx.on_cleanup(lambda: _teardown_stack(cfn, idp, stack_a))

    status_a = _wait_terminal(cfn, stack_a, ctx)
    assert status_a == "CREATE_COMPLETE", f"stack A ended {status_a!r}, expected 'CREATE_COMPLETE'"
    outputs = _stack_outputs(cfn, stack_a)
    pool_id, client_id = outputs["UserPoolId"], outputs["ClientId"]

    pool = idp.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert pool.get("DeletionProtection") == "ACTIVE", (
        f"deployed pool DeletionProtection is {pool.get('DeletionProtection')!r}, expected 'ACTIVE'"
    )

    # Data plane: the deployed pool + client really authenticate a user.
    username = ctx.unique_name("sim2real-user-")
    idp.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=_PASSWORD, MessageAction="SUPPRESS"
    )
    idp.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=_PASSWORD, Permanent=True
    )
    auth = idp.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
    )
    result = auth.get("AuthenticationResult") or {}
    assert result.get("AccessToken"), f"AdminInitiateAuth returned no AccessToken: {auth!r}"
    who = idp.get_user(AccessToken=result["AccessToken"])
    assert who["Username"] == username, (
        f"access token resolved to {who['Username']!r}, expected {username!r}"
    )

    # The rule Stack B relies on, at the API: no CallbackURLs -> InvalidOAuthFlowException,
    # nothing created; with one CallbackURL (positive control) -> accepted.
    bad_name = ctx.unique_name("sim2real-oauth-nocb-")
    oauth = dict(
        UserPoolId=pool_id,
        GenerateSecret=False,
        AllowedOAuthFlowsUserPoolClient=True,
        AllowedOAuthFlows=["code"],
        AllowedOAuthScopes=["openid"],
        SupportedIdentityProviders=["COGNITO"],
    )
    code, message = _error(lambda: _create_client_capturing(ctx, idp, ClientName=bad_name, **oauth))
    assert code == "InvalidOAuthFlowException", (
        f"OAuth code-flow client with no CallbackURLs raised {code!r}, "
        f"expected 'InvalidOAuthFlowException'"
    )
    expected_message = "CallbackUrls can not be empty when code flow or implicit flow is selected"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    names = {c["ClientName"] for c in _list_clients(idp, pool_id)}
    assert bad_name not in names, f"rejected client {bad_name!r} exists anyway: {sorted(names)!r}"
    good = _create_client_capturing(
        ctx, idp, ClientName=ctx.unique_name("sim2real-oauth-cb-"),
        CallbackURLs=["https://example.com/callback"], **oauth,
    )
    assert good.get("AllowedOAuthFlows") == ["code"], (
        f"control client with a CallbackURL came back with flows {good.get('AllowedOAuthFlows')!r}"
    )

    # ---- Delete A while protected: client goes, pool refuses, stack DELETE_FAILED.
    cfn.delete_stack(StackName=stack_a)
    status_a = _wait_terminal(cfn, stack_a, ctx)
    assert status_a == "DELETE_FAILED", (
        f"deleting a stack whose pool has DeletionProtection=ACTIVE ended {status_a!r}, "
        f"expected 'DELETE_FAILED'"
    )
    last = _last_resource_status(cfn, stack_a)
    assert last.get("Pool") == "DELETE_FAILED", (
        f"Pool's last stack event is {last.get('Pool')!r}, expected 'DELETE_FAILED' ({last!r})"
    )
    assert last.get("Client") == "DELETE_COMPLETE", (
        f"Client's last stack event is {last.get('Client')!r}, expected 'DELETE_COMPLETE' ({last!r})"
    )

    survived = idp.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert survived["Id"] == pool_id and survived.get("DeletionProtection") == "ACTIVE", (
        f"after the failed delete the pool reads {survived.get('Id')!r} / "
        f"{survived.get('DeletionProtection')!r}, expected {pool_id!r} / 'ACTIVE'"
    )
    user = idp.admin_get_user(UserPoolId=pool_id, Username=username)
    assert user["Username"] == username, f"user did not survive the failed delete: {user!r}"
    code, message = _error(
        lambda: idp.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": _PASSWORD},
        )
    )
    assert code == "ResourceNotFoundException", (
        f"auth through the client the failed delete removed raised {code!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    expected_message = f"User pool client {client_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # A DELETE_FAILED stack refuses UpdateStack (ValidationError), so protection has to be
    # lifted through UpdateUserPool, not the template.
    tpl_a["Resources"]["Pool"]["Properties"]["DeletionProtection"] = "INACTIVE"
    code, message = _error(lambda: cfn.update_stack(StackName=stack_a, TemplateBody=json.dumps(tpl_a)))
    assert code == "ValidationError", (
        f"UpdateStack on a DELETE_FAILED stack raised {code!r}, expected 'ValidationError'"
    )
    expected_message = f"Stack:{stack_a} is in DELETE_FAILED state and can not be updated."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    still = cfn.describe_stacks(StackName=stack_a)["Stacks"][0]["StackStatus"]
    assert still == "DELETE_FAILED", f"refused update moved the stack to {still!r}"

    # Lift protection on the pool itself, then the retried delete converges.
    idp.update_user_pool(UserPoolId=pool_id, DeletionProtection="INACTIVE")
    lifted = idp.describe_user_pool(UserPoolId=pool_id)["UserPool"].get("DeletionProtection")
    assert lifted == "INACTIVE", f"UpdateUserPool left DeletionProtection {lifted!r}"
    cfn.delete_stack(StackName=stack_a)
    status_a = _wait_terminal(cfn, stack_a, ctx)
    assert status_a == "DELETE_COMPLETE", (
        f"retried delete after lifting protection ended {status_a!r}, expected 'DELETE_COMPLETE'"
    )
    code, message = _error(lambda: idp.describe_user_pool(UserPoolId=pool_id))
    assert code == "ResourceNotFoundException", (
        f"DescribeUserPool on the deleted stack's pool raised {code!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    expected_message = f"User pool {pool_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # ---- Stack B: the client fails, the stack rolls back, the pool it made is gone.
    status_b = _wait_terminal(cfn, stack_b, ctx)
    assert status_b == "ROLLBACK_COMPLETE", (
        f"stack with an OAuth client lacking CallbackURLs ended {status_b!r}, "
        f"expected 'ROLLBACK_COMPLETE'"
    )
    events_b = _events(cfn, stack_b)
    client_states = [e["ResourceStatus"] for e in events_b if e["LogicalResourceId"] == "Client"]
    assert "CREATE_FAILED" in client_states and "CREATE_COMPLETE" not in client_states, (
        f"Client resource went through {client_states!r}, expected CREATE_FAILED and never "
        f"CREATE_COMPLETE"
    )
    pool_events = [e for e in events_b if e["LogicalResourceId"] == "Pool"]
    pool_states = [e["ResourceStatus"] for e in pool_events]
    assert "CREATE_COMPLETE" in pool_states and pool_states[-1] == "DELETE_COMPLETE", (
        f"Pool resource went through {pool_states!r}, expected CREATE_COMPLETE then a final "
        f"DELETE_COMPLETE from the rollback"
    )
    pool_b_ids = {e["PhysicalResourceId"] for e in pool_events if e.get("PhysicalResourceId")}
    assert len(pool_b_ids) == 1, f"rolled-back Pool had physical ids {sorted(pool_b_ids)!r}"
    pool_b_id = pool_b_ids.pop()
    code, message = _error(lambda: idp.describe_user_pool(UserPoolId=pool_b_id))
    assert code == "ResourceNotFoundException", (
        f"DescribeUserPool on rolled-back pool {pool_b_id!r} raised {code!r}, "
        f"expected 'ResourceNotFoundException'"
    )
    expected_message = f"User pool {pool_b_id} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    remaining = [p for p in _list_pools(idp) if p["Name"] == name_b]
    assert remaining == [], f"ListUserPools still shows pools named {name_b!r}: {remaining!r}"


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        resp = fn()
    except Exception as exc:  # botocore ClientError carries .response
        err = getattr(exc, "response", {}).get("Error", {})
        if not err.get("Code"):
            raise
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"call was expected to fail but succeeded: {resp!r}")


def _create_client_capturing(ctx, idp: Any, **kw: Any) -> dict:
    """Create a client and register its delete at once, so a wrongly accepted one cannot leak."""
    client = idp.create_user_pool_client(**kw)["UserPoolClient"]
    ctx.on_cleanup(
        lambda: _quiet(
            lambda: idp.delete_user_pool_client(
                UserPoolId=client["UserPoolId"], ClientId=client["ClientId"]
            )
        )
    )
    return client


def _quiet(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except Exception as exc:
        code = getattr(exc, "response", {}).get("Error", {}).get("Code")
        if code != "ResourceNotFoundException":
            raise


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_terminal(cfn: Any, stack_id: str, ctx: Any = None) -> str:
    """Poll until the stack leaves *_IN_PROGRESS; with ctx, the wait ends before the run's budget."""
    wait_s = _TERMINAL_WAIT_S if ctx is None else _budget_s(ctx, _TERMINAL_WAIT_S)
    deadline = time.time() + wait_s
    while True:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            return status
        if time.time() > deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"stack {stack_id} leaving {status!r}: the run budget ended first; not graded")
            raise AssertionError(f"stack {stack_id} still {status!r} after {wait_s:.0f}s")
        time.sleep(1.0)


def _stack_outputs(cfn: Any, stack_id: str) -> dict[str, str]:
    desc = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


def _events(cfn: Any, stack_id: str) -> list[dict]:
    """All stack events, oldest first."""
    out: list[dict] = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        out.extend(page["StackEvents"])
    return list(reversed(out))


def _last_resource_status(cfn: Any, stack_id: str) -> dict[str, str]:
    last: dict[str, str] = {}
    for e in _events(cfn, stack_id):
        last[e["LogicalResourceId"]] = e["ResourceStatus"]
    return last


def _list_clients(idp: Any, pool_id: str) -> list[dict]:
    out: list[dict] = []
    for page in idp.get_paginator("list_user_pool_clients").paginate(
        UserPoolId=pool_id, PaginationConfig={"PageSize": 60}
    ):
        out.extend(page["UserPoolClients"])
    return out


def _list_pools(idp: Any) -> list[dict]:
    out: list[dict] = []
    for page in idp.get_paginator("list_user_pools").paginate(MaxResults=60):
        out.extend(page["UserPools"])
    return out


def _teardown_stack(cfn: Any, idp: Any, stack_id: str) -> None:
    """Lift any pool protection, delete the stack, and raise if it does not converge."""
    try:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status.endswith("_IN_PROGRESS"):
            status = _wait_terminal(cfn, stack_id)
        for r in cfn.describe_stack_resources(StackName=stack_id)["StackResources"]:
            if r["ResourceType"] == "AWS::Cognito::UserPool" and r.get("PhysicalResourceId"):
                _quiet(
                    lambda: idp.update_user_pool(
                        UserPoolId=r["PhysicalResourceId"], DeletionProtection="INACTIVE"
                    )
                )
        cfn.delete_stack(StackName=stack_id)
        final = _wait_terminal(cfn, stack_id)
        if final != "DELETE_COMPLETE":
            raise RuntimeError(f"stack {stack_id} ended {final!r} on teardown")
    except Exception as exc:
        teardown_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if (
            teardown_code not in ("ResourceNotFoundException",)
            and not any(t in teardown_code for t in ("NotFound", "NoSuch", "NonExistent", "DoesNotExist"))
        ):
            raise RuntimeError(
                f"teardown of stack {stack_id} failed: {type(exc).__name__}: {exc}"
            ) from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
