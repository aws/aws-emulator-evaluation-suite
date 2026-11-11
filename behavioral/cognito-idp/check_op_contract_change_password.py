"""op-contract-changePassword."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-changePassword"
GROUP = "error-semantics"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ChangePassword rotates a user's password when PreviousPassword matches, and the
    new password authenticates afterward; a wrong PreviousPassword is rejected."""
    cognito = ctx.client("cognito-idp")
    pool = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pool"},
    )["UserPool"]
    pool_id = pool["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]
    client_id = client["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    old_password = "OldPass!23"
    new_password = "NewPass!456"
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, TemporaryPassword=old_password, MessageAction="SUPPRESS"
    )
    cognito.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=old_password, Permanent=True)

    auth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": old_password},
    )
    access_token = auth["AuthenticationResult"]["AccessToken"]

    # distinct error boundary: wrong previous password is rejected
    code = _client_error(
        lambda: cognito.change_password(
            AccessToken=access_token, PreviousPassword="WrongPass!23", ProposedPassword=new_password
        )
    )
    assert code.get("Code") == "NotAuthorizedException", code
    assert code.get("Message") == "Incorrect username or password.", code.get("Message")

    # effect absent: the rejected attempt did not rotate the password
    still_old = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": old_password},
    )
    assert "AccessToken" in still_old["AuthenticationResult"]

    # success path: correct previous password rotates it
    resp = cognito.change_password(
        AccessToken=access_token, PreviousPassword=old_password, ProposedPassword=new_password
    )
    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 200

    reauth = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": new_password},
    )
    assert "AccessToken" in reauth["AuthenticationResult"]

    # the old password no longer authenticates
    old_code = _client_error(
        lambda: cognito.admin_initiate_auth(
            UserPoolId=pool_id,
            ClientId=client_id,
            AuthFlow="ADMIN_USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": old_password},
        )
    )
    assert old_code.get("Code") == "NotAuthorizedException", old_code
    assert old_code.get("Message") == "Incorrect username or password.", old_code.get("Message")


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
