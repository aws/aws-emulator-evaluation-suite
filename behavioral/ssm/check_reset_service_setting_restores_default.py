"""reset-service-setting-restores-default."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "reset-service-setting-restores-default"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ssm-service-settings")
def run(ctx) -> None:
    """UpdateServiceSetting sets high-throughput-enabled to "true" (Status=Customized);
    ResetServiceSetting restores the documented default SettingValue="false", Status="Default"."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    setting_id = (
        f"arn:aws:ssm:{ctx.region}:{account_id}:"
        "servicesetting/ssm/parameter-store/high-throughput-enabled"
    )
    ctx.on_cleanup(lambda: ssm.reset_service_setting(SettingId=setting_id))

    ssm.update_service_setting(SettingId=setting_id, SettingValue="true")

    customized = _poll_until(
        lambda: ssm.get_service_setting(SettingId=setting_id)["ServiceSetting"],
        lambda s: s["SettingValue"] == "true",
        timeout_s=30.0,
        interval_s=2.0,
        what="UpdateServiceSetting to take effect (SettingValue -> 'true')",
    )
    assert customized["SettingValue"] == "true", (
        f"expected SettingValue='true' after UpdateServiceSetting, got {customized['SettingValue']!r}"
    )
    assert customized["Status"] == "Customized", (
        f"expected Status='Customized' after UpdateServiceSetting, got {customized['Status']!r}"
    )

    ssm.reset_service_setting(SettingId=setting_id)

    reset = _poll_until(
        lambda: ssm.get_service_setting(SettingId=setting_id)["ServiceSetting"],
        lambda s: s["Status"] == "Default",
        timeout_s=30.0,
        interval_s=2.0,
        what="ResetServiceSetting to take effect (Status -> 'Default')",
    )
    assert reset["Status"] == "Default", (
        f"expected Status='Default' after ResetServiceSetting, got {reset['Status']!r}"
    )
    assert reset["SettingValue"] == "false", (
        f"expected SettingValue='false' (documented default) after ResetServiceSetting, "
        f"got {reset['SettingValue']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last observed: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
