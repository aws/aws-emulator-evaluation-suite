"""delete-account-password-policy."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-account-password-policy"
GROUP = 'password_policy'
SERVICES = ['iam']


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iam-password-policy")
def run(ctx) -> None:
    """DeleteAccountPasswordPolicy removes the custom policy, so Get answers NoSuchEntity, and a
    second delete is rejected NoSuchEntity. Any pre-existing policy is restored afterward."""
    iam = ctx.client("iam")
    original = None
    try:
        original = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise

    def _restore():
        if original is None:
            return
        kwargs = {
            "MinimumPasswordLength": original["MinimumPasswordLength"],
            "RequireSymbols": original["RequireSymbols"],
            "RequireNumbers": original["RequireNumbers"],
            "RequireUppercaseCharacters": original["RequireUppercaseCharacters"],
            "RequireLowercaseCharacters": original["RequireLowercaseCharacters"],
            "AllowUsersToChangePassword": original["AllowUsersToChangePassword"],
            "HardExpiry": original.get("HardExpiry", False),
        }
        if "MaxPasswordAge" in original:
            kwargs["MaxPasswordAge"] = original["MaxPasswordAge"]
        if "PasswordReusePrevention" in original:
            kwargs["PasswordReusePrevention"] = original["PasswordReusePrevention"]
        try:
            iam.update_account_password_policy(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_restore)

    # Guarantee a custom policy is present to delete.
    iam.update_account_password_policy(
        MinimumPasswordLength=10,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        AllowUsersToChangePassword=True,
    )
    fetched = iam.get_account_password_policy()["PasswordPolicy"]
    assert fetched["MinimumPasswordLength"] == 10, f"put didn't stick: {fetched}"

    # Success path: delete it -> account reverts to the default (no custom) policy.
    iam.delete_account_password_policy()
    # Each operation answers its own fixed NoSuchEntity text: GetAccountPasswordPolicy names the
    # account's password policy by domain, DeleteAccountPasswordPolicy names the account policy.
    code_after_delete, message_after_delete = _error(lambda: iam.get_account_password_policy())
    assert code_after_delete == "NoSuchEntity", (
        f"expected the account to revert to no custom policy after delete, got {code_after_delete}"
    )
    expected_get = f"The Password Policy with domain name {ctx.account} cannot be found."
    assert message_after_delete == expected_get, (
        f"GetAccountPasswordPolicy after delete: expected {expected_get!r}, got {message_after_delete!r}"
    )

    # Error boundary: a SECOND delete, with nothing left to delete, is rejected.
    code_double_delete, message_double_delete = _error(lambda: iam.delete_account_password_policy())
    assert code_double_delete == "NoSuchEntity", (
        f"expected NoSuchEntity deleting an already-absent custom password policy, got {code_double_delete}"
    )
    expected_delete = "The account policy with name PasswordPolicy cannot be found."
    assert message_double_delete == expected_delete, (
        f"second DeleteAccountPasswordPolicy: expected {expected_delete!r}, got {message_double_delete!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
