"""auth-flow-not-enabled-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

PASSWORD = "Sup3r-Secret-Passw0rd!"

CHECK = "auth-flow-not-enabled-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

SRP_ONLY_FLOWS = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
WITH_ADMIN_FLOWS = SRP_ONLY_FLOWS + ["ALLOW_ADMIN_USER_PASSWORD_AUTH"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminInitiateAuth with a flow missing from the client's ExplicitAuthFlows is refused with
    InvalidParameterException "Auth flow not enabled for this client", while the same call
    authenticates before the flow is removed and after it is restored."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), DeletionProtection="INACTIVE", UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(WITH_ADMIN_FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    c.admin_set_user_password(UserPoolId=pool_id, Username=username, Password=PASSWORD, Permanent=True)

    def _admin_auth():
        return c.admin_initiate_auth(UserPoolId=pool_id, ClientId=client_id, AuthFlow="ADMIN_USER_PASSWORD_AUTH", AuthParameters={"USERNAME": username, "PASSWORD": PASSWORD})

    def _assert_token_works(auth_result, label):
        # independent read at the destination: the mutating call's own response is never the
        # verdict, so exercise the returned access token through a different operation.
        token = (auth_result or {}).get("AuthenticationResult", {}).get("AccessToken")
        assert token, f"{label}: AdminInitiateAuth returned no AccessToken: {auth_result!r}"
        who = c.get_user(AccessToken=token)
        assert who.get("Username") == username, (
            f"{label}: GetUser with the issued AccessToken resolved to "
            f"{who.get('Username')!r}, not {username!r}"
        )

    # positive control: the flow is allowed, so the call must succeed and the token must work.
    _assert_token_works(_admin_auth(), "positive control")

    # break exactly one thing: drop ADMIN_USER_PASSWORD_AUTH from ExplicitAuthFlows.
    c.update_user_pool_client(UserPoolId=pool_id, ClientId=client_id, ExplicitAuthFlows=list(SRP_ONLY_FLOWS))

    try:
        blocked = _admin_auth()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        code, msg = err.get("Code"), err.get("Message")
    else:
        raise AssertionError(
            "expected InvalidParameterException for ADMIN_USER_PASSWORD_AUTH on a client that "
            f"no longer allows it, but AdminInitiateAuth returned tokens: {blocked!r}"
        )
    assert code == "InvalidParameterException", (
        "expected InvalidParameterException for ADMIN_USER_PASSWORD_AUTH on a client "
        f"that does not allow it, got {code}"
    )
    assert msg == 'Auth flow not enabled for this client', f"expected the exact {code} message, got {msg!r}"

    # restore: re-enable the flow and demand the identical call succeeds again, proving the
    # rejection above was scoped to the flow and not a broken pool/user/client.
    c.update_user_pool_client(UserPoolId=pool_id, ClientId=client_id, ExplicitAuthFlows=list(WITH_ADMIN_FLOWS))
    _assert_token_works(_admin_auth(), "restore")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
