"""put-account-setting-default-service-long-arn-format-disabled-refused."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-account-setting-default-service-long-arn-format-disabled-refused"
GROUP = "account-settings"
SERVICES = ["ecs"]

_NO_DISABLE = ("InvalidParameterException", "You can no longer disable Long Arn settings")


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control",
      "resource:account-singleton:ecs-account-settings")
def run(ctx) -> None:
    """PutAccountSettingDefault refuses serviceLongArnFormat=disabled and leaves the
    account default read back as enabled; the same call with value=enabled succeeds
    and echoes name and value.
    """
    ecs = ctx.client("ecs")
    name = "serviceLongArnFormat"

    def _effective_value():
        settings = ecs.list_account_settings(name=name, effectiveSettings=True)["settings"]
        assert settings, f"ListAccountSettings returned no entry for {name!r}: {settings!r}"
        return settings[0]

    baseline = _effective_value()
    assert baseline["value"] == "enabled", (
        f"expected the {name!r} default to already be 'enabled' (it can never be disabled), "
        f"got {baseline!r}"
    )

    ctx.on_cleanup(lambda: ecs.put_account_setting_default(name=name, value=baseline["value"]))

    expect_error(lambda: ecs.put_account_setting_default(name=name, value="disabled"), *_NO_DISABLE)

    unchanged = _effective_value()
    assert unchanged["name"] == name, f"expected name {name!r} unchanged, got {unchanged!r}"
    assert unchanged["value"] == "enabled", (
        f"expected the refused call to leave {name!r} at 'enabled', got {unchanged!r}"
    )

    accepted = ecs.put_account_setting_default(name=name, value="enabled")["setting"]
    assert accepted["name"] == name, f"expected PutAccountSettingDefault to echo name {name!r}, got {accepted!r}"
    assert accepted["value"] == "enabled", (
        f"expected PutAccountSettingDefault to echo value 'enabled', got {accepted!r}"
    )

    confirmed = _effective_value()
    assert confirmed["name"] == name, f"expected name {name!r} after the accepted call, got {confirmed!r}"
    assert confirmed["value"] == "enabled", (
        f"expected the accepted call to read back as 'enabled', got {confirmed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
