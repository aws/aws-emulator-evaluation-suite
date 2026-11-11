"""update-account-settings-invalid-value-rejected."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "update-account-settings-invalid-value-rejected"
GROUP = "error-semantics"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:appconfig-account-settings")
def run(ctx) -> None:
    """UpdateAccountSettings with ProtectionPeriodInMinutes below 15, sent past client-side
    validation, raises the service's BadRequestException and is never applied, while the same call
    with 15 succeeds.
    """
    appconfig = ctx.client("appconfig")
    raw = ctx.client("appconfig", config=Config(parameter_validation=False))
    before = appconfig.get_account_settings()

    rejected_value = {"Enabled": True, "ProtectionPeriodInMinutes": 5}
    err = _error(lambda: raw.update_account_settings(DeletionProtection=rejected_value))
    assert err["Code"] == "BadRequestException", (
        f"expected BadRequestException for ProtectionPeriodInMinutes below the "
        f"documented minimum of 15, got {err!r}"
    )
    expected_message = (
        "1 validation error detected: Value '5' at 'deletionProtection.protectionPeriodInMinutes' "
        "failed to satisfy constraint: Member must have value greater than or equal to 15"
    )
    assert err["Message"] == expected_message, f"expected message {expected_message!r}, got {err['Message']!r}"

    after = appconfig.get_account_settings()
    assert after["DeletionProtection"] != rejected_value, (
        "a rejected update must not have applied the invalid value"
    )
    assert after["DeletionProtection"].get("ProtectionPeriodInMinutes") != 5, (
        "the out-of-range ProtectionPeriodInMinutes must never be persisted"
    )

    # Positive control: the same shape of call with a valid value succeeds.
    ctx.on_cleanup(
        lambda: appconfig.update_account_settings(DeletionProtection=before["DeletionProtection"])
    )
    valid = appconfig.update_account_settings(
        DeletionProtection={
            "Enabled": before["DeletionProtection"]["Enabled"],
            "ProtectionPeriodInMinutes": 15,
        }
    )
    assert valid["DeletionProtection"]["ProtectionPeriodInMinutes"] == 15, (
        f"expected the positive control to persist ProtectionPeriodInMinutes=15, got "
        f"{valid['DeletionProtection'].get('ProtectionPeriodInMinutes')!r}"
    )


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected a rejection, call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
