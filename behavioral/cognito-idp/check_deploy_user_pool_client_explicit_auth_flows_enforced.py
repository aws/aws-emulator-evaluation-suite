"""deploy-user-pool-client-explicit-auth-flows-enforced."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-user-pool-client-explicit-auth-flows-enforced"
GROUP = "deploy"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed client limited to ADMIN_USER_PASSWORD_AUTH + REFRESH_TOKEN_AUTH rejects
    USER_PASSWORD_AUTH with InvalidParameterException while both allowed flows work; enabling the
    flow via UpdateUserPoolClient makes the identical call succeed."""
    stack_name = ctx.unique_name("sim2real-cog-authflows-")
    template = json.dumps(
        {
            "Resources": {
                "Pool": {
                    "Type": "AWS::Cognito::UserPool",
                    "Properties": {
                        "UserPoolName": stack_name + "-pool",
                        "DeletionProtection": "INACTIVE",
                    },
                },
                "PoolClient": {
                    "Type": "AWS::Cognito::UserPoolClient",
                    "Properties": {
                        "ClientName": stack_name + "-client",
                        "UserPoolId": {"Ref": "Pool"},
                        "ExplicitAuthFlows": [
                            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
                            "ALLOW_REFRESH_TOKEN_AUTH",
                        ],
                        "GenerateSecret": False,
                    },
                },
            },
            "Outputs": {
                "UserPoolId": {"Value": {"Ref": "Pool"}},
                "UserPoolClientId": {"Value": {"Ref": "PoolClient"}},
            },
        }
    )
    outputs = _deploy_cfn(ctx, stack_name, template)
    pool_id = outputs["UserPoolId"]
    client_id = outputs["UserPoolClientId"]

    cognito = ctx.client("cognito-idp")
    client_desc = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=client_id)[
        "UserPoolClient"
    ]
    assert set(client_desc["ExplicitAuthFlows"]) == {
        "ALLOW_ADMIN_USER_PASSWORD_AUTH",
        "ALLOW_REFRESH_TOKEN_AUTH",
    }

    username = ctx.unique_name("sim2real-cog-authuser-")
    password = "Str0ng!Passw0rd456"
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS", TemporaryPassword=password
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )

    admin_auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    refresh_token = admin_auth["AuthenticationResult"]["RefreshToken"]

    code, message = _error(
        lambda: cognito.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
    )
    assert code == "InvalidParameterException", f"unexpected code: {code!r}"
    expected_message = "USER_PASSWORD_AUTH flow not enabled for this client"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    refreshed = cognito.initiate_auth(
        ClientId=client_id,
        AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": refresh_token},
    )
    assert refreshed["AuthenticationResult"]["AccessToken"]

    # The ExplicitAuthFlows change does not reach InitiateAuth instantly; the retry waits for it.
    cognito.update_user_pool_client(
        UserPoolId=pool_id,
        ClientId=client_id,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
        ],
    )
    restored = _retry_until_flow_enabled(cognito, client_id, username, password)
    assert restored["AuthenticationResult"]["AccessToken"]


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _retry_until_flow_enabled(cognito, client_id: str, username: str, password: str) -> dict:
    deadline = time.monotonic() + 60
    last_code = None
    while time.monotonic() < deadline:
        try:
            return cognito.initiate_auth(
                ClientId=client_id,
                AuthFlow="USER_PASSWORD_AUTH",
                AuthParameters={"USERNAME": username, "PASSWORD": password},
            )
        except ClientError as exc:
            last_code = exc.response["Error"]["Code"]
            if last_code != "InvalidParameterException":
                raise
            time.sleep(3)
    raise AssertionError(
        "USER_PASSWORD_AUTH still rejected 60s after UpdateUserPoolClient enabled it "
        f"(last code={last_code!r})"
    )


def _deploy_cfn(ctx, stack_name: str, template_body: str) -> dict:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    deadline = time.monotonic() + 600
    status = None
    while time.monotonic() < deadline:
        desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        status = desc["StackStatus"]
        if status == "CREATE_COMPLETE":
            return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
        if status in ("ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_FAILED"):
            raise AssertionError(f"stack {stack_name} failed to create: {status}")
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE (last status={status})")


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise
        return
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return
        if desc["StackStatus"] == "DELETE_COMPLETE":
            return
        time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
