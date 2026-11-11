"""update-service-setting-unknown-id-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-service-setting-unknown-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

# A real, always-present service setting used as the positive control.
_REAL_SETTING_SUFFIX = "ssm/parameter-store/high-throughput-enabled"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ssm-service-settings")
def run(ctx) -> None:
    """UpdateServiceSetting for a SettingId that SSM never provisioned is rejected
    with ServiceSettingNotFound and creates no new setting, while a real SettingId
    in the same account updates successfully."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    real_setting_id = f"arn:aws:ssm:{ctx.region}:{account_id}:servicesetting/{_REAL_SETTING_SUFFIX}"
    bogus_setting_id = (
        f"arn:aws:ssm:{ctx.region}:{account_id}:servicesetting/ssm/parameter-store/sim2real-behav-no-such-setting"
    )

    # Capture the real setting's actual pre-existing state so cleanup restores exactly
    # that, rather than unconditionally resetting an account-global singleton to its
    # AWS-managed default and clobbering a customization this run did not make.
    original = ssm.get_service_setting(SettingId=real_setting_id)["ServiceSetting"]
    original_value = original["SettingValue"]
    original_status = original["Status"]

    def _restore():
        if original_status == "Default":
            ssm.reset_service_setting(SettingId=real_setting_id)
        else:
            ssm.update_service_setting(SettingId=real_setting_id, SettingValue=original_value)

    ctx.on_cleanup(_restore)

    # Break exactly one thing: an unrecognized SettingId.
    code, message = _error(
        lambda: ssm.update_service_setting(SettingId=bogus_setting_id, SettingValue="true")
    )
    assert code == "ServiceSettingNotFound", f"expected ServiceSettingNotFound, got {code!r}"
    assert message == "", f"unexpected message: {message!r}"

    # Effect absent: the bogus id still resolves to nothing -- no setting was created.
    get_code, get_message = _error(lambda: ssm.get_service_setting(SettingId=bogus_setting_id))
    assert get_code == "ServiceSettingNotFound", f"expected ServiceSettingNotFound, got {get_code!r}"
    assert get_message == "", f"unexpected message: {get_message!r}"

    # Positive control: the real setting id in the same account updates successfully.
    ssm.update_service_setting(SettingId=real_setting_id, SettingValue="true")
    updated = _poll_until(
        lambda: ssm.get_service_setting(SettingId=real_setting_id)["ServiceSetting"],
        lambda s: s["SettingValue"] == "true",
        timeout_s=30,
    )
    assert updated["Status"] == "Customized", f"expected Status Customized, got {updated['Status']!r}"


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last}")


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
