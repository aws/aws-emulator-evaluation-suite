"""op-contract-put-account-setting-default."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-put-account-setting-default"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecs-account-settings")
def run(ctx) -> None:
    """PutAccountSettingDefault changes the default ListAccountSettings(effectiveSettings)
    returns; an unsupported value is rejected (InvalidParameterException), default unchanged."""
    ecs = ctx.client("ecs")

    before = ecs.list_account_settings(name="containerInsights", effectiveSettings=True).get("settings", [])
    before_value = before[0]["value"] if before else "disabled"
    new_value = "disabled" if before_value != "disabled" else "enabled"

    ctx.on_cleanup(lambda: ecs.put_account_setting_default(name="containerInsights", value=before_value))

    put_resp = ecs.put_account_setting_default(name="containerInsights", value=new_value)["setting"]
    assert put_resp["name"] == "containerInsights", put_resp
    assert put_resp["value"] == new_value, put_resp

    after = ecs.list_account_settings(name="containerInsights", effectiveSettings=True)["settings"]
    assert after and after[0]["value"] == new_value, after

    code, message = _error(lambda: ecs.put_account_setting_default(
        name="containerInsights", value="sim2real-not-a-real-value"
    ))
    assert code == "InvalidParameterException", code
    assert message == "Invalid setting 'value'", message

    still = ecs.list_account_settings(name="containerInsights", effectiveSettings=True)["settings"]
    assert still and still[0]["value"] == new_value, still


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"]["Message"]
    raise AssertionError(f"expected ClientError, call unexpectedly succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
