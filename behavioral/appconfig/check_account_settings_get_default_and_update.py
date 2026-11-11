"""account-settings-get-default-and-update."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-settings-get-default-and-update"
GROUP = "account-settings"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:appconfig-account-settings")
def run(ctx) -> None:
    """GetAccountSettings returns the account's current DeletionProtection and
    VendedMetrics settings, and a value written by UpdateAccountSettings is visible
    on the very next GetAccountSettings call (persisted, not merely echoed back).
    """
    appconfig = ctx.client("appconfig")

    before = appconfig.get_account_settings()
    assert isinstance(before["DeletionProtection"]["Enabled"], bool), (
        f"DeletionProtection.Enabled must be a bool, got {before['DeletionProtection']['Enabled']!r}"
    )
    assert isinstance(before["DeletionProtection"]["ProtectionPeriodInMinutes"], int), (
        "DeletionProtection.ProtectionPeriodInMinutes must be an int, got "
        f"{before['DeletionProtection']['ProtectionPeriodInMinutes']!r}"
    )
    # VendedMetrics is only populated once it has been configured at least once --
    # a fresh/never-configured account omits the "Enabled" key entirely rather than
    # defaulting it in the response, so fall back to the documented default (False).
    before_vended_enabled = before.get("VendedMetrics", {}).get("Enabled", False)
    assert isinstance(before_vended_enabled, bool), (
        f"VendedMetrics.Enabled must be a bool, got {before_vended_enabled!r}"
    )

    original_deletion_protection = before["DeletionProtection"]
    original_vended_metrics = {"Enabled": before_vended_enabled}

    def _restore():
        appconfig.update_account_settings(
            DeletionProtection=original_deletion_protection,
            VendedMetrics=original_vended_metrics,
        )

    ctx.on_cleanup(_restore)

    flipped_deletion_protection = not original_deletion_protection["Enabled"]
    flipped_vended_metrics = not before_vended_enabled
    updated = appconfig.update_account_settings(
        DeletionProtection={
            "Enabled": flipped_deletion_protection,
            "ProtectionPeriodInMinutes": 30,
        },
        VendedMetrics={"Enabled": flipped_vended_metrics},
    )
    assert updated["DeletionProtection"]["Enabled"] == flipped_deletion_protection, (
        f"UpdateAccountSettings response DeletionProtection.Enabled expected "
        f"{flipped_deletion_protection}, got {updated['DeletionProtection']['Enabled']!r}"
    )
    assert updated["DeletionProtection"]["ProtectionPeriodInMinutes"] == 30, (
        "UpdateAccountSettings response DeletionProtection.ProtectionPeriodInMinutes "
        f"expected 30, got {updated['DeletionProtection']['ProtectionPeriodInMinutes']!r}"
    )
    assert updated["VendedMetrics"]["Enabled"] == flipped_vended_metrics, (
        f"UpdateAccountSettings response VendedMetrics.Enabled expected "
        f"{flipped_vended_metrics}, got {updated['VendedMetrics']['Enabled']!r}"
    )

    after = appconfig.get_account_settings()
    assert after["DeletionProtection"]["Enabled"] == flipped_deletion_protection, (
        f"GetAccountSettings after update expected DeletionProtection.Enabled="
        f"{flipped_deletion_protection}, got {after['DeletionProtection']['Enabled']!r}"
    )
    assert after["DeletionProtection"]["ProtectionPeriodInMinutes"] == 30, (
        "GetAccountSettings after update expected DeletionProtection."
        f"ProtectionPeriodInMinutes=30, got {after['DeletionProtection']['ProtectionPeriodInMinutes']!r}"
    )
    assert after.get("VendedMetrics", {}).get("Enabled") == flipped_vended_metrics, (
        f"GetAccountSettings after update expected VendedMetrics.Enabled="
        f"{flipped_vended_metrics}, got {after.get('VendedMetrics', {}).get('Enabled')!r}"
    )
    assert after != before, "GetAccountSettings must reflect the persisted update, not stale state"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
