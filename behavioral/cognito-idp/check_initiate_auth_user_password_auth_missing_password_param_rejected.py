"""initiate-auth-user-password-auth-missing-password-param-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "initiate-auth-user-password-auth-missing-password-param-rejected"
GROUP = "overly-permissive"
SERVICES = ["cognito-idp"]

PASSWORD = "Sup3r-Secret-Passw0rd!"
USER_AUTH_FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _error(fn):
    """Call fn(); return its (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """InitiateAuth USER_PASSWORD_AUTH with no PASSWORD key in AuthParameters is refused with
    InvalidParameterException and its exact message, while the same AuthParameters plus
    PASSWORD signs the user in.
    """
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda _p=pool_id: idp.delete_user_pool(UserPoolId=_p))
    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
        ExplicitAuthFlows=list(USER_AUTH_FLOWS),
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: idp.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    idp.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: idp.admin_delete_user(UserPoolId=_p, Username=_u))
    idp.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    code, message = _error(
        lambda: idp.initiate_auth(
            ClientId=client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username},
        )
    )
    assert code == "InvalidParameterException", (
        f"InitiateAuth with no PASSWORD in AuthParameters: expected InvalidParameterException, got {code}"
    )
    expected_message = "Missing required parameter PASSWORD"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    control = idp.initiate_auth(
        ClientId=client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD},
    )
    control_token = control.get("AuthenticationResult", {}).get("AccessToken")
    assert control_token, (
        f"positive control failed: the same AuthParameters plus PASSWORD did not return an "
        f"AccessToken: {control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
