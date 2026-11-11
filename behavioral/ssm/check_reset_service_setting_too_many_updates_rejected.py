"""reset-service-setting-too-many-updates-rejected."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reset-service-setting-too-many-updates-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_SETTING_ID = "/ssm/documents/console/public-sharing-permission"
# AWS sends TooManyUpdates with an empty message.
_TOO_MANY_UPDATES_MESSAGE = ""


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ssm-service-settings")
def run(ctx) -> None:
    """A burst of concurrent Update/ResetServiceSetting calls on one SettingId accepts at least one
    writer, refuses any other only with TooManyUpdates and its exact message, and leaves a value an
    accepted writer set; a later update restores the original value."""
    ssm = ctx.client("ssm")

    original_value = ssm.get_service_setting(SettingId=_SETTING_ID)["ServiceSetting"].get(
        "SettingValue", "Disable"
    )

    def _restore():
        try:
            ssm.update_service_setting(SettingId=_SETTING_ID, SettingValue=original_value)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ServiceSettingNotFound":
                raise

    ctx.on_cleanup(_restore)

    ssm.reset_service_setting(SettingId=_SETTING_ID)
    default_setting = _poll_until(
        lambda: ssm.get_service_setting(SettingId=_SETTING_ID)["ServiceSetting"],
        lambda setting: setting.get("Status") == "Default",
        timeout_s=15.0,
        interval_s=1.0,
    )
    default_value = default_setting["SettingValue"]

    def _racer(i):
        if i % 3 == 0:
            value = default_value
            call = lambda: ssm.reset_service_setting(SettingId=_SETTING_ID)  # noqa: E731
        else:
            value = "Enable" if i % 2 == 0 else "Disable"
            call = lambda: ssm.update_service_setting(SettingId=_SETTING_ID, SettingValue=value)  # noqa: E731
        try:
            call()
            return ("ok", value)
        except ClientError as exc:
            return ("err", (exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    with ThreadPoolExecutor(max_workers=24) as pool:
        results = list(pool.map(_racer, range(24)))

    accepted = {value for kind, value in results if kind == "ok"}
    refused = [error for kind, error in results if kind == "err"]
    assert accepted, f"expected at least one concurrent racer to be accepted, got {results}"
    # Overlapping writers may be refused; serialized writers are all accepted.
    for code, message in refused:
        assert code == "TooManyUpdates", f"a refused racer must get TooManyUpdates with its exact message, got {refused}"
        assert message == _TOO_MANY_UPDATES_MESSAGE, f"a refused racer must get TooManyUpdates with its exact message, got {refused}"
    after_burst = _poll_until(
        lambda: ssm.get_service_setting(SettingId=_SETTING_ID)["ServiceSetting"]["SettingValue"],
        lambda value: value in accepted,
        timeout_s=30.0,
        interval_s=1.0,
    )
    assert after_burst in accepted, f"final value {after_burst!r} is not an accepted writer's {accepted}"

    # The burst may leave the setting mid-contention (still throttling the very next
    # write); poll the restore call itself until it is accepted, then poll the
    # read-back until it actually reflects the restored value -- no fixed sleeps.
    _poll_until(
        lambda: _try_restore(ssm, original_value),
        lambda restored: restored,
        timeout_s=30.0,
        interval_s=1.0,
    )
    final = _poll_until(
        lambda: ssm.get_service_setting(SettingId=_SETTING_ID)["ServiceSetting"]["SettingValue"],
        lambda value: value == original_value,
        timeout_s=30.0,
        interval_s=1.0,
    )
    assert final == original_value, f"expected restored value {original_value}, got {final}"


def _try_restore(ssm, value):
    try:
        ssm.update_service_setting(SettingId=_SETTING_ID, SettingValue=value)
        return True
    except ClientError:
        return False


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
