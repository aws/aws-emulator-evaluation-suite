"""admin-initiate-auth-wrong-password-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

PASSWORD = "Sup3r-Secret-Passw0rd!"

CHECK = "admin-initiate-auth-wrong-password-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

ADMIN_AUTH_FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminInitiateAuth with a wrong password is refused with NotAuthorizedException and the exact
    message, while the correct password on the same pool and client authenticates."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(ADMIN_AUTH_FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    control = c.admin_initiate_auth(UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH", AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD})
    assert "AuthenticationResult" in control, (
        f"positive control: expected the correct password to authenticate, got {control.get('ChallengeName')}"
    )

    try:
        c.admin_initiate_auth(UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH", AuthParameters={"USERNAME": username, "PASSWORD": "Wr0ng-Passw0rd!"})
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException for a bad password, got {code}"
    )
    expected_message = "Incorrect username or password."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
