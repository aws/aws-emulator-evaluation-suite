"""account-setting-put-and-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-setting-put-and-list"
GROUP = 'account-settings'
SERVICES = ['ecs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecs-account-settings")
def run(ctx) -> None:
    """PutAccountSetting persists a setting that then shows up via
    ListAccountSettings for the caller."""
    ecs = ctx.client("ecs")

    def _restore():
        ecs.put_account_setting(name="containerInsights", value="disabled")

    ctx.on_cleanup(_restore)

    resp = ecs.put_account_setting(name="containerInsights", value="enabled")
    setting = resp["setting"]
    assert setting["value"] == "enabled"

    listed = ecs.list_account_settings(name="containerInsights")["settings"]
    values = [s["value"] for s in listed if s["name"] == "containerInsights"]
    assert "enabled" in values, f"expected 'enabled' in listed settings: {listed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
