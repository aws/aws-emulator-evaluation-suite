"""op-contract-adminSetUserPassword."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-adminSetUserPassword"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AdminSetUserPassword transitions FORCE_CHANGE_PASSWORD->CONFIRMED on success and
    rejects a password that violates the pool's password policy, without changing the
    user's active password."""
    cognito = ctx.client("cognito-idp")
    pool_id = _create_user_pool(ctx, cognito)
    client_id = _create_client(ctx, cognito, pool_id)
    username = ctx.unique_name("sim2real-user-")
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword="TempPass!23",
        MessageAction="SUPPRESS",
    )
    before = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert before["UserStatus"] == "FORCE_CHANGE_PASSWORD", before["UserStatus"]

    # success path: setting a permanent password transitions the user to CONFIRMED
    permanent_password = "NewPass!456"
    resp = cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=permanent_password, Permanent=True
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200, resp["ResponseMetadata"]
    after = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after["UserStatus"] == "CONFIRMED", after["UserStatus"]

    # distinct error boundary: password fails the pool's password policy
    code = _client_error(
        lambda: cognito.admin_set_user_password(
            UserPoolId=pool_id, Username=username, Password="abc", Permanent=True
        )
    )
    assert code.get("Code") == "InvalidPasswordException", code
    assert code.get("Message") == "Password does not conform to policy: Password not long enough", code.get("Message")

    # effect-absent, via an independent read at the destination: the rejected call must
    # not have changed the active password. Authenticating with the password set above
    # must still succeed.
    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": permanent_password},
    )
    assert "AuthenticationResult" in auth, f"expected tokens, got challenge {auth.get('ChallengeName')}"


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_user_pool(ctx, cognito):
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _create_client(ctx, cognito, pool_id):
    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]
    client_id = client["ClientId"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool_client(UserPoolId=pool_id, ClientId=client_id))
    return client_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
