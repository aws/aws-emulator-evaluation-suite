"""admin-set-weak-password-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "admin-set-weak-password-fails"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

WEAK_PASSWORD = "abc"
STRONG_PASSWORD = "Str0ng!Passw0rd#2024"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: AdminSetUserPassword MUST enforce the password policy."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda _id=pool_id: c.delete_user_pool(UserPoolId=_id))
    username = ctx.unique_name("sim2real-behav-cip-user-")
    c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
    ctx.on_cleanup(lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u))

    try:
        c.admin_set_user_password(
            UserPoolId=pool_id, Username=username, Password=WEAK_PASSWORD, Permanent=True
        )
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidPasswordException", (
        f"expected InvalidPasswordException for a weak password, got {code}"
    )
    expected_message = "Password does not conform to policy: Password not long enough"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    # The rejected call must not have moved the user out of FORCE_CHANGE_PASSWORD.
    got = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert got["UserStatus"] == "FORCE_CHANGE_PASSWORD", (
        f"expected user to stay in FORCE_CHANGE_PASSWORD, got {got['UserStatus']}"
    )

    # Positive control: the identical call, same pool and user, succeeds once the
    # password satisfies the policy -- proving the rejection above is the password
    # policy at work, not AdminSetUserPassword failing or denying universally.
    c.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=STRONG_PASSWORD, Permanent=True
    )
    after = c.admin_get_user(UserPoolId=pool_id, Username=username)
    assert after["UserStatus"] == "CONFIRMED", (
        f"expected user to reach CONFIRMED after a policy-satisfying password, got {after['UserStatus']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
