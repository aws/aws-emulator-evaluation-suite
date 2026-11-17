"""cfn-user-pool-client-generate-secret-toggle-updates-in-place-and-replaces."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-user-pool-client-generate-secret-toggle-updates-in-place-and-replaces"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-idp"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


def _wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def _delete_stack(cf, stack_id):
    cf.delete_stack(StackName=stack_id)
    status = _wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def _outputs(cf, stack_id) -> dict:
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _template(*, pool_name: str, client_name: str, generate_secret: bool,
             refresh_token_validity: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Pool": {
                "Type": "AWS::Cognito::UserPool",
                "Properties": {
                    "UserPoolName": pool_name,
                    "DeletionProtection": "INACTIVE",
                },
            },
            "PoolClient": {
                "Type": "AWS::Cognito::UserPoolClient",
                "Properties": {
                    "ClientName": client_name,
                    "UserPoolId": {"Ref": "Pool"},
                    "GenerateSecret": generate_secret,
                    "ExplicitAuthFlows": ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
                    "RefreshTokenValidity": refresh_token_validity,
                },
            },
        },
        "Outputs": {
            "PoolRef": {"Value": {"Ref": "Pool"}},
            "ClientRef": {"Value": {"Ref": "PoolClient"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN update changing only RefreshTokenValidity keeps a UserPoolClient's ClientId; one
    flipping GenerateSecret replaces it with a new ClientId carrying the latest RefreshTokenValidity
    and a fresh secret, and the old ClientId is gone.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html
    """
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")
    stack_name = ctx.unique_name("sim2real-behav-cogclientgs-")
    pool_name = ctx.unique_name("sim2real-behav-cogclientgspool-")
    client_name = ctx.unique_name("sim2real-behav-cogclientgsclient-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(
            pool_name=pool_name, client_name=client_name,
            generate_secret=False, refresh_token_validity=30,
        ),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_id))
    status = _wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"

    outputs = _outputs(cfn, stack_id)
    pool_id = outputs["PoolRef"]
    original_client_id = outputs["ClientRef"]

    original = cognito.describe_user_pool_client(
        UserPoolId=pool_id, ClientId=original_client_id
    )["UserPoolClient"]
    assert original["RefreshTokenValidity"] == 30, (
        f"expected RefreshTokenValidity 30, got {original['RefreshTokenValidity']!r}"
    )
    assert not original.get("ClientSecret"), (
        f"GenerateSecret=False should produce no ClientSecret, got {original.get('ClientSecret')!r}"
    )

    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(
            pool_name=pool_name, client_name=client_name,
            generate_secret=False, refresh_token_validity=60,
        ),
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"in-place update ended {status!r}"

    outputs = _outputs(cfn, stack_id)
    assert outputs["ClientRef"] == original_client_id, (
        f"an in-place RefreshTokenValidity update should keep ClientId "
        f"{original_client_id!r}, got {outputs['ClientRef']!r}"
    )
    updated = cognito.describe_user_pool_client(
        UserPoolId=pool_id, ClientId=original_client_id
    )["UserPoolClient"]
    assert updated["RefreshTokenValidity"] == 60, (
        f"expected the updated RefreshTokenValidity 60, got {updated['RefreshTokenValidity']!r}"
    )

    cfn.update_stack(
        StackName=stack_id,
        TemplateBody=_template(
            pool_name=pool_name, client_name=client_name,
            generate_secret=True, refresh_token_validity=60,
        ),
    )
    status = _wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"replacement update ended {status!r}"

    outputs = _outputs(cfn, stack_id)
    replaced_client_id = outputs["ClientRef"]
    assert replaced_client_id != original_client_id, (
        f"flipping GenerateSecret should replace the client with a new ClientId, "
        f"still got {replaced_client_id!r}"
    )

    replaced = cognito.describe_user_pool_client(
        UserPoolId=pool_id, ClientId=replaced_client_id
    )["UserPoolClient"]
    assert replaced.get("ClientSecret"), (
        f"GenerateSecret=True on the replacement should produce a non-empty ClientSecret, "
        f"got {replaced.get('ClientSecret')!r}"
    )
    assert replaced["RefreshTokenValidity"] == 60, (
        f"the replacement should carry the latest RefreshTokenValidity 60, "
        f"got {replaced['RefreshTokenValidity']!r}"
    )

    client_gone = ("ResourceNotFoundException", "User pool client does not exist.")
    _expect_error(
        lambda: cognito.describe_user_pool_client(
            UserPoolId=pool_id, ClientId=original_client_id
        ),
        *client_gone,
    )

    _delete_stack(cfn, stack_id)

    pool_gone = ("ResourceNotFoundException", f"User pool {pool_id} does not exist.")
    _expect_error(lambda: cognito.describe_user_pool(UserPoolId=pool_id), *pool_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
