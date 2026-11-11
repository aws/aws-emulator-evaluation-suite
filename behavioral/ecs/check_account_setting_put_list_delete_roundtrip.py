"""account-setting-put-list-delete-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "account-setting-put-list-delete-roundtrip"
GROUP = "state"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecs-account-settings")
def run(ctx) -> None:
    """PutAccountSetting scoped to the caller's principal is visible via
    ListAccountSettings and reverted by DeleteAccountSetting."""
    ecs = ctx.client("ecs")
    setting_name = "containerInsights"

    def _current_value():
        resp = ecs.list_account_settings(name=setting_name, effectiveSettings=False)
        for setting in resp.get("settings", []):
            if setting["name"] == setting_name and "principalArn" in setting:
                return setting["value"]
        return None

    ctx.on_cleanup(lambda: _safe_delete(ecs, setting_name))

    put = ecs.put_account_setting(name=setting_name, value="enabled")["setting"]
    assert put["name"] == setting_name, f"expected setting name {setting_name!r}, got {put!r}"
    assert put["value"] == "enabled", f"expected PutAccountSetting to echo 'enabled', got {put!r}"

    assert _current_value() == "enabled", "PutAccountSetting value not visible via ListAccountSettings"

    ecs.put_account_setting(name=setting_name, value="disabled")
    assert _current_value() == "disabled", "second PutAccountSetting value not visible via ListAccountSettings"

    ecs.delete_account_setting(name=setting_name)
    assert _current_value() is None, "DeleteAccountSetting should remove the per-principal override"


def _safe_delete(ecs, setting_name):
    try:
        ecs.delete_account_setting(name=setting_name)
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "InvalidParameterException"
            and "Referenced setting doesn't exist" in err.get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
