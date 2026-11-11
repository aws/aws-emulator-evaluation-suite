"""update-user-pool-policy-persists."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-user-pool-policy-persists"
GROUP = 'user-pool-lifecycle'
SERVICES = ['cognito-idp']

# A password that satisfies the DEFAULT Cognito password policy (min length 8,
# upper, lower, number, symbol) but NOT the 20-char policy this check installs.
DEFAULT_PASSWORD = "TempPassw0rd!23"


def _error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message) if a ClientError is raised. An
    unexpected SUCCESS raises, because an over-permissive target accepting a call real AWS refuses is
    the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_user_pool(idp, ctx, **kwargs):
    """CreateUserPool + register DeleteUserPool cleanup; returns the UserPool dict."""
    name = ctx.unique_name("sim2real-behav-cip-pool-")
    pool = idp.create_user_pool(
        PoolName=name,
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        **kwargs,
    )["UserPool"]
    ctx.on_cleanup(lambda _id=pool["Id"]: idp.delete_user_pool(UserPoolId=_id))
    return pool


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateUserPool mutates the password policy; the new policy persists and is enforced,
    the rejected user never exists, and reverting the policy restores the old behaviour."""
    idp = ctx.client("cognito-idp")
    pool = _create_user_pool(idp, ctx)
    original_policy = idp.describe_user_pool(UserPoolId=pool["Id"])["UserPool"]["Policies"][
        "PasswordPolicy"
    ]

    # Positive control: the pool's starting policy accepts DEFAULT_PASSWORD.
    control_user = ctx.unique_name("sim2real-behav-cip-user-control-")
    control_resp = idp.admin_create_user(
        UserPoolId=pool["Id"],
        Username=control_user,
        TemporaryPassword=DEFAULT_PASSWORD,
        MessageAction="SUPPRESS",
    )
    assert control_resp["User"]["Username"] == control_user, (
        f"expected the positive control to create {control_user} under the starting policy, "
        f"got {control_resp['User']}"
    )

    idp.update_user_pool(
        UserPoolId=pool["Id"],
        Policies={
            "PasswordPolicy": {
                "MinimumLength": 20,
                "RequireUppercase": True,
                "RequireLowercase": True,
                "RequireNumbers": True,
                "RequireSymbols": True,
            }
        },
    )

    desc = idp.describe_user_pool(UserPoolId=pool["Id"])["UserPool"]
    assert desc["Policies"]["PasswordPolicy"]["MinimumLength"] == 20, (
        f"expected MinimumLength 20, got {desc['Policies']['PasswordPolicy']}"
    )

    # The tightened policy must actually be enforced: the old 15-char password now fails.
    target_user = ctx.unique_name("sim2real-behav-cip-user-")
    code, message = _error(
        lambda: idp.admin_create_user(
            UserPoolId=pool["Id"],
            Username=target_user,
            TemporaryPassword=DEFAULT_PASSWORD,
            MessageAction="SUPPRESS",
        )
    )
    assert code == "InvalidPasswordException", (
        f"expected the updated password policy to be enforced, got {code}"
    )
    assert message == "Password did not conform with password policy: Password not long enough", (
        f"expected the exact {code} message for a too-short password, got {message!r}"
    )

    # The effect is absent: an independent read shows the rejected user was never created.
    absent_code, absent_message = _error(
        lambda: idp.admin_get_user(UserPoolId=pool["Id"], Username=target_user)
    )
    assert absent_code == "UserNotFoundException", (
        f"expected {target_user} to not exist after the rejected create, got {absent_code}"
    )
    assert absent_message == "User does not exist.", (
        f"expected the exact {absent_code} message, got {absent_message!r}"
    )

    # Restore the original policy, and the identical call now succeeds.
    idp.update_user_pool(UserPoolId=pool["Id"], Policies={"PasswordPolicy": original_policy})
    restored_resp = idp.admin_create_user(
        UserPoolId=pool["Id"],
        Username=target_user,
        TemporaryPassword=DEFAULT_PASSWORD,
        MessageAction="SUPPRESS",
    )
    assert restored_resp["User"]["Username"] == target_user, (
        f"expected the identical call to succeed after restoring the original policy, "
        f"got {restored_resp['User']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
