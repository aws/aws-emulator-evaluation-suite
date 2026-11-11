"""update-service-setting-too-many-updates-rejected."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-service-setting-too-many-updates-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

# AWS sends TooManyUpdates with an empty message.
_TOO_MANY_UPDATES_MESSAGE = ""


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ssm-service-settings")
def run(ctx) -> None:
    """Concurrent UpdateServiceSetting calls on one setting accept at least one writer, refuse any
    other only with TooManyUpdates and its exact message, and leave an accepted value; once the burst
    settles an identical call succeeds again."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    setting_id = (
        f"arn:aws:ssm:{ctx.region}:{account_id}:servicesetting/ssm/parameter-store/high-throughput-enabled"
    )

    original_value = ssm.get_service_setting(SettingId=setting_id)["ServiceSetting"]["SettingValue"]
    ctx.on_cleanup(lambda: ssm.update_service_setting(SettingId=setting_id, SettingValue=original_value))

    # positive control: a single, isolated update succeeds and persists
    toggled_value = "false" if original_value == "true" else "true"
    ssm.update_service_setting(SettingId=setting_id, SettingValue=toggled_value)
    got = ssm.get_service_setting(SettingId=setting_id)["ServiceSetting"]["SettingValue"]
    assert got == toggled_value, f"expected positive-control update to persist {toggled_value!r}, got {got!r}"

    # a burst of concurrent updates on the same setting id; overlapping writers may be refused
    results = _fire_concurrent_updates(ctx, setting_id, original_value, toggled_value, n=30)
    accepted = {value for value, error in results if error is None}
    refused = [error for _, error in results if error is not None]
    assert accepted, f"expected at least one concurrent racer to be accepted, got {results}"
    for code, message in refused:
        assert code == "TooManyUpdates", f"a refused racer must get TooManyUpdates with its exact message, got {refused}"
        assert message == _TOO_MANY_UPDATES_MESSAGE, f"a refused racer must get TooManyUpdates with its exact message, got {refused}"
    after_burst = ssm.get_service_setting(SettingId=setting_id)["ServiceSetting"]["SettingValue"]
    assert after_burst in accepted, f"final value {after_burst!r} is not an accepted writer's {accepted}"

    # restore leg: once the burst settles, the identical call succeeds again -- proves
    # TooManyUpdates was a transient single-writer throttle, not a permanent break.
    deadline = time.monotonic() + 30
    while True:
        try:
            ssm.update_service_setting(SettingId=setting_id, SettingValue=original_value)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TooManyUpdates" or time.monotonic() >= deadline:
                raise
            time.sleep(1)

    restored = ssm.get_service_setting(SettingId=setting_id)["ServiceSetting"]["SettingValue"]
    assert restored == original_value, (
        f"expected the post-burst update to persist the original value {original_value!r}, got {restored!r}"
    )


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
    return None


def _fire_concurrent_updates(ctx, setting_id: str, value_a: str, value_b: str, n: int) -> list:
    ssm = ctx.client("ssm")

    def _one(i: int):
        value = value_a if i % 2 == 0 else value_b
        return value, _error(lambda: ssm.update_service_setting(SettingId=setting_id, SettingValue=value))

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_one, i) for i in range(n)]
        return [future.result() for future in as_completed(futures)]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
