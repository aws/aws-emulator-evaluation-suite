"""admin-confirm-signup-wrong-status-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-confirm-signup-wrong-status-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: AdminConfirmSignUp on a non-UNCONFIRMED user MUST fail."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    client_id = c.create_user_pool_client(UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-behav-cip-client-"), ExplicitAuthFlows=["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"], GenerateSecret=False)["UserPoolClient"]["ClientId"]
    ctx.on_cleanup(lambda _p=pool_id, _c=client_id: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c))

    # Positive control: a self-signed-up UNCONFIRMED user on the same pool confirms cleanly,
    # proving the account/credentials and AdminConfirmSignUp itself are healthy — so the
    # rejection below is specific to the wrong-status user, not AdminConfirmSignUp always failing.
    control_username = ctx.unique_name("sim2real-behav-cip-control-")
    c.sign_up(ClientId=client_id, Username=control_username, Password="Sup3r-Secret-Passw0rd!")
    ctx.on_cleanup(lambda _p=pool_id, _u=control_username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    control_status = c.admin_get_user(UserPoolId=pool_id, Username=control_username)["UserStatus"]
    assert control_status == "UNCONFIRMED", f"expected control user UNCONFIRMED, got {control_status}"
    c.admin_confirm_sign_up(UserPoolId=pool_id, Username=control_username)
    control_status = c.admin_get_user(UserPoolId=pool_id, Username=control_username)["UserStatus"]
    assert control_status == "CONFIRMED", (
        f"positive control failed: expected AdminConfirmSignUp to move the UNCONFIRMED control "
        f"user to CONFIRMED, got {control_status}"
    )

    # AdminCreateUser produces a user in FORCE_CHANGE_PASSWORD status, not UNCONFIRMED.
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))
    before_status = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert before_status == "FORCE_CHANGE_PASSWORD", f"expected FORCE_CHANGE_PASSWORD, got {before_status}"

    code, message = _error(
        lambda: c.admin_confirm_sign_up(UserPoolId=pool_id, Username=username)
    )
    assert (code, message) == ("NotAuthorizedException", "User cannot be confirmed. Current status is FORCE_CHANGE_PASSWORD"), (
        "expected AdminConfirmSignUp on a FORCE_CHANGE_PASSWORD user to fail with "
        f"NotAuthorizedException, got {(code, message)!r}"
    )

    # Independent read at the destination: the effect must be absent — the user must still be
    # FORCE_CHANGE_PASSWORD, not silently advanced to CONFIRMED by the rejected call.
    after_status = c.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert after_status == "FORCE_CHANGE_PASSWORD", (
        f"expected status to remain FORCE_CHANGE_PASSWORD after the rejected AdminConfirmSignUp, "
        f"got {after_status}"
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
