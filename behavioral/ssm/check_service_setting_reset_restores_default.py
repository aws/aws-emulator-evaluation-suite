"""service-setting-reset-restores-default."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "service-setting-reset-restores-default"
GROUP = "state-machine"
SERVICES = ["ssm"]

_SETTING_ID = "/ssm/parameter-store/high-throughput-enabled"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ssm-service-settings")
def run(ctx) -> None:
    """UpdateServiceSetting followed by ResetServiceSetting restores the setting's
    default value and 'Default' status, as observed by GetServiceSetting."""
    ssm = ctx.client("ssm")

    # Establish a known-default baseline regardless of any state left over from
    # other tests that may have run against this account.
    ssm.reset_service_setting(SettingId=_SETTING_ID)
    baseline = ssm.get_service_setting(SettingId=_SETTING_ID)["ServiceSetting"]
    default_value = baseline["SettingValue"]
    assert baseline["Status"] == "Default", (
        f"expected Default status right after reset, got {baseline['Status']!r}"
    )

    other_value = "false" if default_value == "true" else "true"
    ssm.update_service_setting(SettingId=_SETTING_ID, SettingValue=other_value)

    updated = ssm.get_service_setting(SettingId=_SETTING_ID)["ServiceSetting"]
    assert updated["SettingValue"] == other_value, (
        f"expected SettingValue={other_value!r} after update, got {updated['SettingValue']!r}"
    )
    assert updated["Status"] == "Customized", (
        f"expected Customized status after update, got {updated['Status']!r}"
    )

    ctx.on_cleanup(lambda: ssm.reset_service_setting(SettingId=_SETTING_ID))

    ssm.reset_service_setting(SettingId=_SETTING_ID)
    restored = ssm.get_service_setting(SettingId=_SETTING_ID)["ServiceSetting"]
    assert restored["SettingValue"] == default_value, (
        f"expected SettingValue={default_value!r} (default) after reset, "
        f"got {restored['SettingValue']!r}"
    )
    assert restored["Status"] == "Default", (
        f"expected Default status after reset, got {restored['Status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
