"""op-contract-adminUserGlobalSignOut."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminUserGlobalSignOut"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AdminUserGlobalSignOut revokes the user's refresh tokens (a REFRESH_TOKEN_AUTH
    attempt fails afterward) and rejects a nonexistent username."""
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]
    client_id = client["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    password = "TempPass!23"
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=password, MessageAction="SUPPRESS"
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=password, Permanent=True)

    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    refresh_token = auth["AuthenticationResult"]["RefreshToken"]

    # sanity: the refresh token is currently valid
    refreshed = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="REFRESH_TOKEN_AUTH",
        AuthParameters={"REFRESH_TOKEN": refresh_token},
    )
    assert "AccessToken" in refreshed["AuthenticationResult"], (
        f"expected a fresh access token before sign-out, got {refreshed['AuthenticationResult']!r}"
    )

    # success path: global sign-out revokes the refresh token
    resp = cognito.admin_user_global_sign_out(UserPoolId=pool_id, Username=username)
    actual_status = resp["ResponseMetadata"]["HTTPStatusCode"]
    assert actual_status == 200, f"expected AdminUserGlobalSignOut to 200, got {actual_status}"
    code = _client_error(
        lambda: cognito.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": refresh_token},
        )
    )
    assert code.get("Code") == "NotAuthorizedException", f"expected the revoked refresh token to be rejected, got {code}"
    assert code.get("Message") == "Refresh Token has been revoked", code.get("Message")

    # distinct error boundary: nonexistent username
    code2 = _client_error(
        lambda: cognito.admin_user_global_sign_out(UserPoolId=pool_id, Username="no-such-user-xyz")
    )
    assert code2.get("Code") == "UserNotFoundException", f"expected UserNotFoundException, got {code2}"
    assert code2.get("Message") == "User does not exist.", code2.get("Message")


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
