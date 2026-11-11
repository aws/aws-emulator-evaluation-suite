"""configured-password-policy-governs-accepted-passwords."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "configured-password-policy-governs-accepted-passwords"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

USER_AUTH_FLOWS = ["ALLOW_USER_PASSWORD_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

RELAXED_POLICY = {
    "MinimumLength": 6,
    "RequireUppercase": False,
    "RequireLowercase": True,
    "RequireNumbers": False,
    "RequireSymbols": False,
}
STRICT_POLICY = {
    "MinimumLength": 16,
    "RequireUppercase": True,
    "RequireLowercase": True,
    "RequireNumbers": True,
    "RequireSymbols": True,
}
RELAXED_PASSWORD = "abcdef"
STRICT_PASSWORD = "Str1ct-Passw0rd-16!"
# Each entry differs from STRICT_PASSWORD in exactly one policy rule, with the exact
# InvalidPasswordException message AWS returns for that rule.
_POLICY_PREFIX = "Password does not conform to policy: "
STRICT_VIOLATIONS = [
    ("MinimumLength", "Str1ct-P0!", _POLICY_PREFIX + "Password not long enough"),
    ("RequireUppercase", "str1ct-passw0rd-16!", _POLICY_PREFIX + "Password must have uppercase characters"),
    ("RequireLowercase", "STR1CT-PASSW0RD-16!", _POLICY_PREFIX + "Password must have lowercase characters"),
    ("RequireNumbers", "Strict-Password-XY!", _POLICY_PREFIX + "Password must have numeric characters"),
    ("RequireSymbols", "Str1ctPassw0rd1616", _POLICY_PREFIX + "Password must have symbol characters"),
]


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected with InvalidPasswordException, but it SUCCEEDED "
        f"and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The pool's PasswordPolicy decides which passwords are accepted: a relaxed policy accepts and
    signs in with a password the default rejects, and a strict policy refuses each single-rule
    violation with InvalidPasswordException and the exact message."""
    c = ctx.client("cognito-idp")

    def _make_pool(policy: dict) -> tuple[str, str]:
        pid = c.create_user_pool(
            PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
            Policies={"PasswordPolicy": dict(policy)},
            DeletionProtection="INACTIVE",
            UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
        )["UserPool"]["Id"]
        ctx.on_cleanup(lambda _id=pid: c.delete_user_pool(UserPoolId=_id))
        cid = c.create_user_pool_client(
            UserPoolId=pid,
            ClientName=ctx.unique_name("sim2real-behav-cip-client-"),
            ExplicitAuthFlows=list(USER_AUTH_FLOWS),
            GenerateSecret=False,
        )["UserPoolClient"]["ClientId"]
        ctx.on_cleanup(
            lambda _p=pid, _c=cid: c.delete_user_pool_client(UserPoolId=_p, ClientId=_c)
        )
        return pid, cid

    relaxed_pool, relaxed_client = _make_pool(RELAXED_POLICY)
    strict_pool, strict_client = _make_pool(STRICT_POLICY)

    for pool_id, policy in ((relaxed_pool, RELAXED_POLICY), (strict_pool, STRICT_POLICY)):
        stored = c.describe_user_pool(UserPoolId=pool_id)["UserPool"]["Policies"][
            "PasswordPolicy"
        ]
        for key, want in policy.items():
            assert stored.get(key) == want, (
                f"DescribeUserPool must round-trip PasswordPolicy.{key}={want}, got "
                f"{stored.get(key)}"
            )

    def _seed(pool_id: str) -> str:
        username = ctx.unique_name("sim2real-behav-cipuser")
        c.admin_create_user(UserPoolId=pool_id, Username=username, MessageAction="SUPPRESS")
        ctx.on_cleanup(
            lambda _p=pool_id, _u=username: c.admin_delete_user(UserPoolId=_p, Username=_u)
        )
        return username

    # --- relaxed pool: a password the DEFAULT policy would reject must be ACCEPTED ---
    relaxed_user = _seed(relaxed_pool)
    c.admin_set_user_password(
        UserPoolId=relaxed_pool,
        Username=relaxed_user,
        Password=RELAXED_PASSWORD,
        Permanent=True,
    )
    relaxed_status = c.admin_get_user(UserPoolId=relaxed_pool, Username=relaxed_user)[
        "UserStatus"
    ]
    assert relaxed_status == "CONFIRMED", (
        f"the relaxed policy must accept {RELAXED_PASSWORD!r} and confirm the user, got "
        f"UserStatus {relaxed_status}"
    )
    relaxed_result = c.initiate_auth(
        ClientId=relaxed_client,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": relaxed_user, "PASSWORD": RELAXED_PASSWORD},
    )["AuthenticationResult"]
    assert relaxed_result.get("AccessToken"), (
        f"the relaxed policy's password {RELAXED_PASSWORD!r} must authenticate end-to-end"
    )
    # And the relaxed pool's own floor still bites: 5 chars < MinimumLength 6.
    too_short_code, too_short_message = _error(
        lambda: c.admin_set_user_password(
            UserPoolId=relaxed_pool, Username=relaxed_user, Password="abcde", Permanent=True
        )
    )
    assert too_short_code == "InvalidPasswordException", (
        f"even the relaxed policy must enforce MinimumLength=6; expected "
        f"InvalidPasswordException for a 5-character password, got {too_short_code}"
    )
    assert too_short_message == _POLICY_PREFIX + "Password not long enough", (
        f"expected the exact MinimumLength refusal message, got {too_short_message!r}"
    )

    # --- strict pool: break exactly one rule at a time ---
    strict_user = _seed(strict_pool)
    for rule, password, want_message in STRICT_VIOLATIONS:
        code, message = _error(
            lambda _p=password: c.admin_set_user_password(
                UserPoolId=strict_pool, Username=strict_user, Password=_p, Permanent=True
            )
        )
        assert code == "InvalidPasswordException", (
            f"the strict policy must reject {password!r} for violating {rule}; expected "
            f"InvalidPasswordException, got {code}"
        )
        assert message == want_message, (
            f"the strict policy's {rule} refusal must read {want_message!r}, got {message!r}"
        )
        status = c.admin_get_user(UserPoolId=strict_pool, Username=strict_user)["UserStatus"]
        assert status == "FORCE_CHANGE_PASSWORD", (
            f"a rejected password must leave the user in FORCE_CHANGE_PASSWORD, got {status} "
            f"after {password!r}"
        )

    # --- control: the fully compliant password is accepted and authenticates ---
    c.admin_set_user_password(
        UserPoolId=strict_pool,
        Username=strict_user,
        Password=STRICT_PASSWORD,
        Permanent=True,
    )
    strict_status = c.admin_get_user(UserPoolId=strict_pool, Username=strict_user)[
        "UserStatus"
    ]
    assert strict_status == "CONFIRMED", (
        f"the compliant password must confirm the user, got UserStatus {strict_status}"
    )
    strict_result = c.initiate_auth(
        ClientId=strict_client,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": strict_user, "PASSWORD": STRICT_PASSWORD},
    )["AuthenticationResult"]
    assert strict_result.get("AccessToken"), (
        "the compliant strict password must authenticate end-to-end"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
