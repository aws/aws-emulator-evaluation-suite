"""temporary-password-forced-change-window."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "temporary-password-forced-change-window"
GROUP = 'password-ttl'
SERVICES = ['cognito-idp']

PASSWORD = "Str0ngPassw0rd!"
FLOWS = ["ALLOW_ADMIN_USER_PASSWORD_AUTH", "ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _admin_auth(c, pool_id, client_id, username, password):
    """AdminInitiateAuth (ADMIN_USER_PASSWORD_AUTH); returns the FULL response so
    a caller can inspect ChallengeName/Session or AuthenticationResult."""
    return c.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Permanent=False password leaves the user FORCE_CHANGE_PASSWORD and every login gets
    NEW_PASSWORD_REQUIRED; after the challenge sets a new password, the temporary one fails with
    NotAuthorizedException and its exact message and the new one signs in."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), AutoVerifiedAttributes=["email"], UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, TemporaryPassword="Temp0rar1Pass!", MessageAction="SUPPRESS", UserAttributes=[{"Name": "email", "Value": f"{username}@example.com"}])
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    temp_password = "Temp0raryWindow!"
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=temp_password, Permanent=False)
    status1 = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status1 == "FORCE_CHANGE_PASSWORD", status1

    challenge1 = _admin_auth(c, pool_id, client_id, username, temp_password)
    assert challenge1.get("ChallengeName") == "NEW_PASSWORD_REQUIRED", challenge1.get("ChallengeName")

    # Trying again with the SAME temp password before it's changed still
    # yields the same challenge -- it hasn't silently expired or been consumed.
    challenge2 = _admin_auth(c, pool_id, client_id, username, temp_password)
    assert challenge2.get("ChallengeName") == "NEW_PASSWORD_REQUIRED", challenge2.get("ChallengeName")

    final_password = "PermanentWindow0Pass!"
    completed = c.admin_respond_to_auth_challenge(
        UserPoolId=pool_id,
        ClientId=client_id,
        ChallengeName="NEW_PASSWORD_REQUIRED",
        Session=challenge2["Session"],
        ChallengeResponses={"USERNAME": username, "NEW_PASSWORD": final_password},
    )
    assert "AuthenticationResult" in completed, completed

    # Now that the temporary password has been consumed/replaced, using it
    # again is rejected outright rather than still granting a challenge.
    code, message = _error(lambda: _admin_auth(c, pool_id, client_id, username, temp_password))
    assert code == "NotAuthorizedException", (
        f"expected NotAuthorizedException for the superseded temp password, got {code}"
    )
    expected_message = "Incorrect username or password."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    relogin = _admin_auth(c, pool_id, client_id, username, final_password)
    assert relogin["AuthenticationResult"]["AccessToken"], (
        f"expected an AccessToken after re-login with the final password, got {relogin.get('AuthenticationResult')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
