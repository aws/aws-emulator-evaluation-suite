"""admin-set-user-password-weak-password-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "admin-set-user-password-weak-password-rejected"
GROUP = "server-side"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AdminSetUserPassword rejects a password violating the pool's password policy with InvalidPasswordException."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pwpolicy-pool"),
        DeletionProtection="INACTIVE",
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 16,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        },
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-pwpolicy"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    username = ctx.unique_name("sim2real-pwpolicy-user")
    cognito.admin_create_user(
        UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS"
    )
    ctx.on_cleanup(
        lambda: cognito.admin_delete_user(UserPoolId=pool_id, Username=username)
    )

    # Two independent weak passwords, chosen so neither violation shape alone would pass a
    # validator that only checks length: one is too short (and also fails every other rule),
    # the other is long enough but still missing uppercase and symbol characters.
    too_short_password = "abc123"  # violates length, uppercase, and symbol requirements
    missing_classes_password = "alllowercase12345"  # 17 chars: no uppercase, no symbol
    for weak_password, expected_message in (
        (too_short_password, "Password does not conform to policy: Password not long enough"),
        (missing_classes_password, "Password does not conform to policy: Password must have uppercase characters"),
    ):
        code, message = _error(
            lambda _p=weak_password: cognito.admin_set_user_password(
                UserPoolId=pool_id,
                Username=username,
                Password=_p,
                Permanent=True,
            )
        )
        assert code == "InvalidPasswordException", (
            f"expected InvalidPasswordException for policy-violating password {weak_password!r}, "
            f"got {code!r}"
        )
        assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
        # The rejected call must not have moved the user out of FORCE_CHANGE_PASSWORD.
        rejected_status = cognito.admin_get_user(UserPoolId=pool_id, Username=username)[
            "UserStatus"
        ]
        assert rejected_status == "FORCE_CHANGE_PASSWORD", (
            f"expected user to stay in FORCE_CHANGE_PASSWORD after rejecting "
            f"{weak_password!r}, got {rejected_status}"
        )

    # Sanity check: a password that satisfies the policy is accepted (the rejection above
    # is due to the policy check, not some unrelated failure).
    strong_password = "Str0ng!Passw0rd#2024"
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=strong_password, Permanent=True
    )
    user = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert user["UserStatus"] == "CONFIRMED", user["UserStatus"]


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting what AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
