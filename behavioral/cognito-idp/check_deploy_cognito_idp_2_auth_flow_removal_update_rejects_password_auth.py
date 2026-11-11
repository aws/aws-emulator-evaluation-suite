"""deploy-cognito-idp-2-auth-flow-removal-update-rejects-password-auth."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cognito-idp-2-auth-flow-removal-update-rejects-password-auth"
GROUP = "deploy-update"
SERVICES = ["cognito-idp"]

_PASSWORD = "Sim2Real!FlowPass9"
_STACK_TIMEOUT_S = 600


@tags(
    "axis:rejection",
    "cap:c3",
    "concern:data-plane",
    "concern:deploy",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An update_stack that drops ALLOW_USER_PASSWORD_AUTH from a deployed app client takes effect
    in place: the same client id refuses USER_PASSWORD_AUTH afterwards, while the kept
    ADMIN_USER_PASSWORD_AUTH flow still issues tokens."""
    cfn = ctx.client("cloudformation")
    cognito = ctx.client("cognito-idp")
    stack_name = ctx.unique_name("sim2real-cog-flow-")

    created = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(stack_name, allow_user_password=True),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _cleanup_stack(cfn, created["StackId"]))
    stack_id = created["StackId"]

    outputs = _wait_stack(cfn, stack_id, "CREATE_COMPLETE")
    pool_id = outputs["UserPoolId"]
    client_id = outputs["UserPoolClientId"]

    user = ctx.unique_name("sim2real-cog-flowuser-")
    cognito.admin_create_user(UserPoolId=pool_id, Username=user, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda: _delete_user(cognito, pool_id, user))
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=user, Password=_PASSWORD, Permanent=True)

    before = cognito.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": user, "PASSWORD": _PASSWORD},
    )
    assert before.get("AuthenticationResult", {}).get("AccessToken"), (
        f"USER_PASSWORD_AUTH before the update issued no AccessToken: {sorted(before)!r}"
    )

    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack_name, allow_user_password=False))
    outputs = _wait_stack(cfn, stack_id, "UPDATE_COMPLETE")
    assert outputs["UserPoolClientId"] == client_id, (
        f"removing an auth flow replaced the client {client_id!r} -> {outputs['UserPoolClientId']!r}; "
        "ExplicitAuthFlows is an in-place property"
    )
    flows = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)["UserPoolClient"].get(
        "ExplicitAuthFlows", [])
    assert "ALLOW_USER_PASSWORD_AUTH" not in flows, f"client still lists ALLOW_USER_PASSWORD_AUTH: {flows!r}"
    assert "ALLOW_ADMIN_USER_PASSWORD_AUTH" in flows, f"client lost ALLOW_ADMIN_USER_PASSWORD_AUTH: {flows!r}"

    code, message = _error(lambda: cognito.initiate_auth(
        ClientId=client_id, AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": user, "PASSWORD": _PASSWORD},
    ))
    assert code == "InvalidParameterException", (
        f"USER_PASSWORD_AUTH after the flow was removed returned {code!r}, expected 'InvalidParameterException'"
    )
    expected_message = "USER_PASSWORD_AUTH flow not enabled for this client"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: the same client, user and password still authenticate via the kept flow
    after = cognito.admin_initiate_auth(
        UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": user, "PASSWORD": _PASSWORD},
    )
    assert after.get("AuthenticationResult", {}).get("AccessToken"), (
        f"ADMIN_USER_PASSWORD_AUTH on the updated client issued no AccessToken: {sorted(after)!r}"
    )



def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _template(stack_name: str, *, allow_user_password: bool) -> str:
    flows = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
    if allow_user_password:
        flows.insert(0, "ALLOW_USER_PASSWORD_AUTH")
    return json.dumps({
        "Resources": {
            "Pool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {
                    "UserPoolName": stack_name + "-pool",
                    "DeletionProtection": "INACTIVE",
                    "UserPoolTags": {"sim2real": CHECK},
                },
            },
            "Client": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "ClientName": stack_name + "-client",
                    "UserPoolId": {"Ref": "Pool"},
                    "GenerateSecret": False,
                    "ExplicitAuthFlows": flows,
                },
            },
        },
        "Outputs": {
            "UserPoolId": {"Value": {"Ref": "Pool"}},
            "UserPoolClientId": {"Value": {"Ref": "Client"}},
        },
    })


def _wait_stack(cfn, stack_id: str, want: str) -> dict:
    """Poll until the stack leaves *_IN_PROGRESS; a timeout or any other terminal state FAILs."""
    deadline = time.monotonic() + _STACK_TIMEOUT_S
    status = None
    while time.monotonic() < deadline:
        desc = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = desc["StackStatus"]
        if not status.endswith("_IN_PROGRESS"):
            assert status == want, f"stack reached {status!r}, expected {want!r}"
            return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
        time.sleep(5)
    raise AssertionError(f"stack did not reach {want!r} within {_STACK_TIMEOUT_S}s (last status={status!r})")


def _delete_user(cognito, pool_id: str, username: str) -> None:
    try:
        cognito.admin_delete_user(UserPoolId=pool_id, Username=username)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("UserNotFoundException", "ResourceNotFoundException"):
            raise


def _cleanup_stack(cfn, stack_id: str) -> None:
    status = None
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + _STACK_TIMEOUT_S
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in ("DELETE_COMPLETE", "DELETE_FAILED"):
            break
        time.sleep(2)
    if status != "DELETE_COMPLETE":
        raise RuntimeError(f"stack {stack_id} teardown ended in {status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
