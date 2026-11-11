"""service-setting-too-many-updates-rejected."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-setting-too-many-updates-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]

# TooManyUpdates is documented for concurrent updates to a one-update-at-a-time resource; a burst
# of concurrent writes to one SettingId may provoke it.
_SETTING_SUFFIX = "ssm/parameter-store/high-throughput-enabled"
_CONCURRENCY = 40
# AWS sends TooManyUpdates with an empty message.
_TOO_MANY_UPDATES_MESSAGE = ""


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ssm-service-settings")
def run(ctx) -> None:
    """Concurrent Update/ResetServiceSetting calls on one SettingId refuse a writer only with
    TooManyUpdates and its exact message, the final value is one an accepted writer set (or the
    default), and a lone update then succeeds with Status=Customized."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    setting_id = f"arn:aws:ssm:{ctx.region}:{account_id}:servicesetting/{_SETTING_SUFFIX}"

    ssm.reset_service_setting(SettingId=setting_id)
    ctx.on_cleanup(lambda: ssm.reset_service_setting(SettingId=setting_id))

    # Status "Default" means the value equals the account's default (not "never updated"), so
    # the final update must use a value that diverges from it.
    default_setting = _poll_until(
        lambda: ssm.get_service_setting(SettingId=setting_id)["ServiceSetting"],
        lambda s: s.get("Status") == "Default",
        timeout_s=15,
        interval_s=1,
    )
    default_value = default_setting["SettingValue"]

    def _update_or_reset(i: int):
        try:
            if i % 3 == 0:
                ssm.reset_service_setting(SettingId=setting_id)
                return ("ok", "reset")
            value = "true" if i % 2 == 0 else "false"
            ssm.update_service_setting(SettingId=setting_id, SettingValue=value)
            return ("ok", value)
        except ClientError as e:
            return (e.response["Error"]["Code"], e.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=_CONCURRENCY) as pool:
        futures = [pool.submit(_update_or_reset, i) for i in range(_CONCURRENCY)]
        results = [f.result() for f in as_completed(futures)]

    accepted_values = {value for code, value in results if code == "ok" and value != "reset"}
    accepted_reset = any(code == "ok" and value == "reset" for code, value in results)
    refused = [(code, message) for code, message in results if code != "ok"]
    # Overlapping writers may be refused; serialized writers are all accepted.
    for code, message in refused:
        assert code == "TooManyUpdates", f"a refused writer must get TooManyUpdates with its exact message, got {refused}"
        assert message == _TOO_MANY_UPDATES_MESSAGE, f"a refused writer must get TooManyUpdates with its exact message, got {refused}"
    assert accepted_values or accepted_reset, f"expected at least one writer accepted, got {results}"
    if accepted_reset:
        accepted_values.add(default_value)

    final = _poll_until(
        lambda: ssm.get_service_setting(SettingId=setting_id)["ServiceSetting"],
        lambda s: True,
        timeout_s=10,
        interval_s=1,
    )
    assert final["SettingValue"] in accepted_values, (
        f"expected final SettingValue in accepted values {accepted_values}, "
        f"got {final['SettingValue']!r} (possible corruption from a rejected writer)"
    )

    non_default_value = "true" if default_value == "false" else "false"
    ssm.update_service_setting(SettingId=setting_id, SettingValue=non_default_value)
    settled = _poll_until(
        lambda: ssm.get_service_setting(SettingId=setting_id)["ServiceSetting"],
        lambda s: s["SettingValue"] == non_default_value,
        timeout_s=30,
    )
    assert settled["Status"] == "Customized", (
        f"expected Status Customized after setting the non-default value {non_default_value!r}, "
        f"got {settled['Status']!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
