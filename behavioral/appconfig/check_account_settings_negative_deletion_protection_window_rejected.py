"""account-settings-negative-deletion-protection-window-rejected."""
from __future__ import annotations

from typing import Any, Callable

from botocore.config import Config

from behavioral_harness import tags

CHECK = "account-settings-negative-deletion-protection-window-rejected"
GROUP = "overly-permissive"
SERVICES = ["appconfig"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:appconfig-account-settings")
def run(ctx) -> None:
    """UpdateAccountSettings rejects ProtectionPeriodInMinutes outside 15-1440 (-5 and 1441) with
    BadRequestException without mutating settings; the boundary value 15 is accepted and read back."""
    appconfig = ctx.client("appconfig")
    # botocore enforces the model's min (15) client-side, so -5 only reaches the service unvalidated.
    unvalidated = ctx.client("appconfig", config=Config(parameter_validation=False))
    original = appconfig.get_account_settings()
    orig_deletion = dict(original.get("DeletionProtection", {}))
    orig_enabled = orig_deletion.get("Enabled", False)
    orig_period = orig_deletion.get("ProtectionPeriodInMinutes", 60)

    ctx.on_cleanup(
        lambda: appconfig.update_account_settings(
            DeletionProtection={"Enabled": orig_enabled, "ProtectionPeriodInMinutes": orig_period}
        )
    )

    for client, bad_value, expected_code in (
        (unvalidated, -5, "BadRequestException"),
        (appconfig, 1441, "BadRequestException"),
    ):
        code = _error_code(
            lambda c=client, v=bad_value: c.update_account_settings(
                DeletionProtection={"Enabled": True, "ProtectionPeriodInMinutes": v}
            )
        )
        assert code == expected_code, f"value {bad_value}: expected {expected_code}, got {code}"
        after = appconfig.get_account_settings()
        after_period = after.get("DeletionProtection", {}).get("ProtectionPeriodInMinutes", 60)
        assert after_period == orig_period, (
            f"rejected update with {bad_value} must not have mutated ProtectionPeriodInMinutes "
            f"(expected {orig_period}, got {after_period})"
        )

    good = appconfig.update_account_settings(
        DeletionProtection={"Enabled": True, "ProtectionPeriodInMinutes": 15}
    )
    assert good["DeletionProtection"]["ProtectionPeriodInMinutes"] == 15, (
        f"expected the update response to reflect 15, got "
        f"{good['DeletionProtection'].get('ProtectionPeriodInMinutes')}"
    )
    confirmed = appconfig.get_account_settings()
    assert confirmed["DeletionProtection"]["ProtectionPeriodInMinutes"] == 15, (
        f"expected GetAccountSettings to reflect 15, got "
        f"{confirmed['DeletionProtection'].get('ProtectionPeriodInMinutes')}"
    )
    assert confirmed["DeletionProtection"]["Enabled"] is True, (
        f"expected Enabled True after the accepted update, got "
        f"{confirmed['DeletionProtection'].get('Enabled')}"
    )


def _error_code(fn: Callable[[], Any]):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError("expected the update to be rejected but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
