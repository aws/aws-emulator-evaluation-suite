"""update-password-policy-length-above-max-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-password-policy-length-above-max-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "resource:account-singleton:iam-password-policy",
)
def run(ctx) -> None:
    """UpdateAccountPasswordPolicy rejects a MinimumPasswordLength above the documented 128
    maximum, leaving the account's password policy unchanged; 128 itself is accepted."""
    iam = ctx.client("iam")

    original = _capture(iam)
    ctx.on_cleanup(lambda: _restore(iam, original))

    iam.update_account_password_policy(MinimumPasswordLength=10)
    before = iam.get_account_password_policy()["PasswordPolicy"]["MinimumPasswordLength"]
    assert before == 10, f"expected the baseline policy to hold MinimumPasswordLength 10, got {before}"

    code, message = _error(lambda: iam.update_account_password_policy(MinimumPasswordLength=129))
    assert code == "ValidationError", f"expected ValidationError for MinimumPasswordLength 129, got {code}"
    expected = (
        "1 validation error detected: Value at 'minimumPasswordLength' failed to satisfy "
        "constraint: Member must have value less than or equal to 128"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the rejected update must not have changed the account's policy.
    after = iam.get_account_password_policy()["PasswordPolicy"]["MinimumPasswordLength"]
    assert after == 10, f"MinimumPasswordLength changed by a rejected update: 10 -> {after}"

    # Positive control: the documented maximum of 128 is accepted.
    iam.update_account_password_policy(MinimumPasswordLength=128)
    accepted = iam.get_account_password_policy()["PasswordPolicy"]["MinimumPasswordLength"]
    assert accepted == 128, f"expected MinimumPasswordLength 128 to be accepted, got {accepted}"


def _capture(iam):
    try:
        return iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return None
        raise


def _restore(iam, original):
    if original is None:
        try:
            iam.delete_account_password_policy()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
        return
    kwargs = {k: v for k, v in original.items() if k not in ("ExpirePasswords",)}
    iam.update_account_password_policy(**kwargs)


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects MinimumPasswordLength above 128, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
