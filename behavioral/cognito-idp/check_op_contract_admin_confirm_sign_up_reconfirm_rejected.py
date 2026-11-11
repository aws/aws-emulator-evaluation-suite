"""op-contract-admin-confirm-sign-up-reconfirm-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-admin-confirm-sign-up-reconfirm-rejected"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminConfirmSignUp transitions a self-signed-up UNCONFIRMED user to CONFIRMED, and
    rejects re-confirming an already-CONFIRMED user with NotAuthorizedException."""
    idp = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx)
    client_id = _create_pool_client(ctx, pool_id)

    username = ctx.unique_name("sim2real-user-")
    idp.sign_up(ClientId=client_id, Username=username, Password="TestPassw0rd!")

    status = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "UNCONFIRMED", f"expected UNCONFIRMED, got {status}"

    resp = idp.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    http_status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert http_status == 200, f"expected HTTP 200 from AdminConfirmSignUp, got {http_status}"

    status = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "CONFIRMED", f"expected CONFIRMED, got {status}"

    code, message = _error(lambda: idp.admin_confirm_sign_up(UserPoolId=pool_id, Username=username))
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code}"
    assert message == "User cannot be confirmed. Current status is CONFIRMED", message

    status = idp.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "CONFIRMED", f"expected rejected reconfirm to leave status CONFIRMED, got {status}"


def _error(fn):
    """(code, message) of the expected refusal; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_user_pool(ctx) -> str:
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_pool_client(ctx, pool_id: str) -> str:
    idp = ctx.client("cognito-idp")
    return idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        GenerateSecret=False,
        ExplicitAuthFlows=[
            "ALLOW_ADMIN_USER_PASSWORD_AUTH",
            "ALLOW_REFRESH_TOKEN_AUTH",
            "ALLOW_USER_PASSWORD_AUTH",
        ],
    )["UserPoolClient"]["ClientId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
