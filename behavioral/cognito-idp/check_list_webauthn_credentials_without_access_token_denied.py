"""list-webauthn-credentials-without-access-token-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-webauthn-credentials-without-access-token-denied"
GROUP = "negative-classes"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListWebAuthnCredentials rejects a garbage access token with NotAuthorizedException rather
    than succeeding or returning an empty list (ForbiddenException is for AWS WAF rejections)."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-listwa-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-listwa"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"],
    )["UserPoolClient"]["ClientId"]

    username = ctx.unique_name("sim2real-user-")
    password = "Sim2Real-Pwd9!"
    cognito.admin_create_user(
        UserPoolId=pool_id,
        Username=username,
        TemporaryPassword=password,
        MessageAction="SUPPRESS",
    )
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    access_token = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )["AuthenticationResult"]["AccessToken"]

    bogus_token = "not-a-real-access-token-" + "y" * 20
    code, message = _error(lambda: cognito.list_web_authn_credentials(AccessToken=bogus_token))
    assert code == "NotAuthorizedException", f"expected NotAuthorizedException, got {code}"
    expected = "Invalid Access Token"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # positive control: the real access token succeeds and returns an empty credential list
    resp = cognito.list_web_authn_credentials(AccessToken=access_token)
    assert resp["Credentials"] == []


def _error(fn):
    """Call fn(); return its error code. An unexpected SUCCESS raises, because a target accepting
    input real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        err = err.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected NotAuthorizedException but call SUCCEEDED with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
