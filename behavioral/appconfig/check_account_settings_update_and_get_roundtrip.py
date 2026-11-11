"""account-settings-update-and-get-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-settings-update-and-get-roundtrip"
GROUP = "server-side"
SERVICES = ["appconfig"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:appconfig-account-settings")
def run(ctx) -> None:
    """UpdateAccountSettings changes to DeletionProtection and VendedMetrics are immediately
    visible on a subsequent GetAccountSettings call, in both directions of a boolean toggle."""
    appconfig = ctx.client("appconfig")

    original = appconfig.get_account_settings()
    orig_deletion = dict(original.get("DeletionProtection", {}))
    orig_vended = dict(original.get("VendedMetrics", {}))
    orig_enabled = orig_deletion.get("Enabled", False)
    orig_period = orig_deletion.get("ProtectionPeriodInMinutes", 60)
    orig_vended_enabled = orig_vended.get("Enabled", False)

    def _restore() -> None:
        appconfig.update_account_settings(
            DeletionProtection={"Enabled": orig_enabled, "ProtectionPeriodInMinutes": orig_period},
            VendedMetrics={"Enabled": orig_vended_enabled},
        )

    ctx.on_cleanup(_restore)

    new_enabled = not orig_enabled
    new_period = 30 if orig_period != 30 else 45
    new_vended_enabled = not orig_vended_enabled

    update_resp = appconfig.update_account_settings(
        DeletionProtection={"Enabled": new_enabled, "ProtectionPeriodInMinutes": new_period},
        VendedMetrics={"Enabled": new_vended_enabled},
    )
    assert update_resp["DeletionProtection"]["Enabled"] == new_enabled, (
        f"UpdateAccountSettings response DeletionProtection.Enabled: "
        f"expected {new_enabled}, got {update_resp['DeletionProtection']['Enabled']}"
    )
    assert update_resp["DeletionProtection"]["ProtectionPeriodInMinutes"] == new_period, (
        f"UpdateAccountSettings response ProtectionPeriodInMinutes: "
        f"expected {new_period}, got {update_resp['DeletionProtection']['ProtectionPeriodInMinutes']}"
    )
    assert update_resp["VendedMetrics"]["Enabled"] == new_vended_enabled, (
        f"UpdateAccountSettings response VendedMetrics.Enabled: "
        f"expected {new_vended_enabled}, got {update_resp['VendedMetrics'].get('Enabled')}"
    )

    fetched = appconfig.get_account_settings()
    assert fetched["DeletionProtection"]["Enabled"] == new_enabled, (
        f"GetAccountSettings DeletionProtection.Enabled after update: "
        f"expected {new_enabled}, got {fetched['DeletionProtection']['Enabled']}"
    )
    assert fetched["DeletionProtection"]["ProtectionPeriodInMinutes"] == new_period, (
        f"GetAccountSettings ProtectionPeriodInMinutes after update: "
        f"expected {new_period}, got {fetched['DeletionProtection']['ProtectionPeriodInMinutes']}"
    )
    assert fetched["VendedMetrics"]["Enabled"] == new_vended_enabled, (
        f"GetAccountSettings VendedMetrics.Enabled after update: "
        f"expected {new_vended_enabled}, got {fetched['VendedMetrics'].get('Enabled')}"
    )

    # Flip DeletionProtection.Enabled back the other way and confirm the reversal is also
    # reflected immediately -- proves the roundtrip isn't a one-shot fluke.
    flipped_enabled = not new_enabled
    flip_resp = appconfig.update_account_settings(
        DeletionProtection={"Enabled": flipped_enabled, "ProtectionPeriodInMinutes": new_period}
    )
    assert flip_resp["DeletionProtection"]["Enabled"] == flipped_enabled, (
        f"UpdateAccountSettings response DeletionProtection.Enabled after reversal: "
        f"expected {flipped_enabled}, got {flip_resp['DeletionProtection']['Enabled']}"
    )
    refetched = appconfig.get_account_settings()
    assert refetched["DeletionProtection"]["Enabled"] == flipped_enabled, (
        f"GetAccountSettings DeletionProtection.Enabled after reversal: "
        f"expected {flipped_enabled}, got {refetched['DeletionProtection']['Enabled']}"
    )
    assert refetched["DeletionProtection"]["ProtectionPeriodInMinutes"] == new_period, (
        f"GetAccountSettings ProtectionPeriodInMinutes after reversal: "
        f"expected {new_period}, got {refetched['DeletionProtection']['ProtectionPeriodInMinutes']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
