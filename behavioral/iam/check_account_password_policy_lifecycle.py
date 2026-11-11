"""account-password-policy-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-password-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:iam-password-policy")
def run(ctx) -> None:
    """UpdateAccountPasswordPolicy -> GetAccountPasswordPolicy -> DeleteAccountPasswordPolicy
    -> NoSuchEntity-on-get transitions for the account's (singleton) password policy.
    Snapshots and restores whatever policy pre-existed on the account."""
    iam = ctx.client("iam")

    original = _capture_password_policy(iam)
    ctx.on_cleanup(lambda: _apply_password_policy(iam, original))

    test_policy = dict(
        MinimumPasswordLength=10,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        AllowUsersToChangePassword=True,
        MaxPasswordAge=90,
        PasswordReusePrevention=5,
        HardExpiry=False,
    )
    iam.update_account_password_policy(**test_policy)

    fetched = iam.get_account_password_policy()["PasswordPolicy"]
    assert fetched["MinimumPasswordLength"] == 10, f"expected MinimumPasswordLength 10, got {fetched}"
    assert fetched["RequireSymbols"] is True, f"expected RequireSymbols True, got {fetched}"
    assert fetched["RequireNumbers"] is True, f"expected RequireNumbers True, got {fetched}"
    assert fetched["RequireUppercaseCharacters"] is True, f"expected RequireUppercaseCharacters True, got {fetched}"
    assert fetched["RequireLowercaseCharacters"] is True, f"expected RequireLowercaseCharacters True, got {fetched}"
    assert fetched["AllowUsersToChangePassword"] is True, f"expected AllowUsersToChangePassword True, got {fetched}"
    assert fetched["MaxPasswordAge"] == 90, f"expected MaxPasswordAge 90, got {fetched}"
    assert fetched["PasswordReusePrevention"] == 5, f"expected PasswordReusePrevention 5, got {fetched}"
    assert fetched["ExpirePasswords"] is True, "ExpirePasswords must derive true when MaxPasswordAge is set"

    # mutate again to prove it's a live replace, not create-once
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=False,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        AllowUsersToChangePassword=True,
        HardExpiry=False,
    )
    fetched2 = iam.get_account_password_policy()["PasswordPolicy"]
    assert fetched2["MinimumPasswordLength"] == 14, f"expected MinimumPasswordLength 14, got {fetched2}"
    assert fetched2["RequireSymbols"] is False, f"expected RequireSymbols False, got {fetched2}"
    # MaxPasswordAge/PasswordReusePrevention were omitted from this update -> cleared
    assert "MaxPasswordAge" not in fetched2, f"expected MaxPasswordAge cleared by the field-omitting update, got {fetched2}"
    assert fetched2["ExpirePasswords"] is False, f"expected ExpirePasswords False once MaxPasswordAge is cleared, got {fetched2}"

    iam.delete_account_password_policy()
    # IAM's wire error code omits the "Exception" suffix present on the botocore
    # exception class name (the class is NoSuchEntityException, but the
    # response Error.Code is "NoSuchEntity").
    code, message = _error(lambda: iam.get_account_password_policy())
    assert code == "NoSuchEntity", f"expected NoSuchEntity after delete, got {code!r}"
    assert message == f"The Password Policy with domain name {ctx.account} cannot be found.", (
        f"GetAccountPasswordPolicy message after delete: {message!r}"
    )


def _capture_password_policy(iam):
    try:
        return iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return None
        raise


def _apply_password_policy(iam, policy):
    if policy is None:
        try:
            iam.delete_account_password_policy()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise
        return
    kwargs = {
        "MinimumPasswordLength": policy["MinimumPasswordLength"],
        "RequireSymbols": policy["RequireSymbols"],
        "RequireNumbers": policy["RequireNumbers"],
        "RequireUppercaseCharacters": policy["RequireUppercaseCharacters"],
        "RequireLowercaseCharacters": policy["RequireLowercaseCharacters"],
        "AllowUsersToChangePassword": policy["AllowUsersToChangePassword"],
        "HardExpiry": policy.get("HardExpiry", False),
    }
    if "MaxPasswordAge" in policy:
        kwargs["MaxPasswordAge"] = policy["MaxPasswordAge"]
    if "PasswordReusePrevention" in policy:
        kwargs["PasswordReusePrevention"] = policy["PasswordReusePrevention"]
    iam.update_account_password_policy(**kwargs)


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
