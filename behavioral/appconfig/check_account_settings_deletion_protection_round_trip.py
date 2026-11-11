"""account-settings-deletion-protection-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-settings-deletion-protection-round-trip"
GROUP = 'account-settings'
SERVICES = ['appconfig']


def _restore_account_settings(ac, original: dict) -> None:
    try:
        dp = original.get("DeletionProtection", {}) or {}
        ac.update_account_settings(
            DeletionProtection={
                "Enabled": dp.get("Enabled", False),
                "ProtectionPeriodInMinutes": dp.get("ProtectionPeriodInMinutes", 15),
            }
        )
    except Exception:
        pass


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:appconfig-account-settings")
def run(ctx) -> None:
    """UpdateAccountSettings persists DeletionProtection fields visible via GetAccountSettings."""
    ac = ctx.client("appconfig")
    original_settings = ac.get_account_settings()
    try:
        ac.update_account_settings(
            DeletionProtection={"Enabled": True, "ProtectionPeriodInMinutes": 20}
        )
        got = ac.get_account_settings()
        assert got["DeletionProtection"]["Enabled"] is True, (
            f"expected DeletionProtection.Enabled=True after update, got {got['DeletionProtection']['Enabled']!r}"
        )
        assert got["DeletionProtection"]["ProtectionPeriodInMinutes"] == 20, (
            "expected DeletionProtection.ProtectionPeriodInMinutes=20 after update, got "
            f"{got['DeletionProtection']['ProtectionPeriodInMinutes']!r}"
        )
    finally:
        _restore_account_settings(ac, original_settings)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
