"""admin-confirm-signup-twice-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-confirm-signup-twice-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

PASSWORD = "Sup3r-Secret-Passw0rd!"

USER_AUTH_FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: confirming an already-CONFIRMED user MUST fail, and the
    user's status must be unaffected by the rejected re-confirm attempt."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=list(USER_AUTH_FLOWS), GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))
    username = ctx.unique_name("sim2real-behav-cipuser")

    c.sign_up(ClientId=client_id, Username=username, Password=PASSWORD)
    ctx.on_cleanup(lambda: c.admin_delete_user(UserPoolId=pool_id, Username=username))

    status = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "UNCONFIRMED", f"expected UNCONFIRMED before AdminConfirmSignUp, got {status}"

    c.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)

    status = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "CONFIRMED", f"expected CONFIRMED after the first AdminConfirmSignUp, got {status}"

    code, message = _error(
        lambda: c.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    )
    assert (code, message) == ("NotAuthorizedException", "User cannot be confirmed. Current status is CONFIRMED"), (
        f"expected NotAuthorizedException on a second AdminConfirmSignUp, got {(code, message)!r}"
    )

    status = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status == "CONFIRMED", (
        f"expected user status unchanged at CONFIRMED after the rejected re-confirm, got {status}"
    )


def _error(fn):
    """Call fn(); return its (code, message). A call that succeeds raises: a target that
    accepts what AWS refuses must fail loudly, never as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
