"""reset-service-setting-unknown-setting-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reset-service-setting-unknown-setting-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ssm-service-settings")
def run(ctx) -> None:
    """ResetServiceSetting for a non-existent setting id returns ServiceSettingNotFound instead
    of a no-op success, while resetting a real service setting still works."""
    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    real_setting_id = (
        f"arn:aws:ssm:{ctx.region}:{account_id}:servicesetting/ssm/parameter-store/high-throughput-enabled"
    )

    # the setting is account-wide: a customized value is written back after the check
    prior = ssm.get_service_setting(SettingId=real_setting_id)["ServiceSetting"]
    if prior["Status"] != "Default":
        ctx.on_cleanup(
            lambda: ssm.update_service_setting(SettingId=real_setting_id, SettingValue=prior["SettingValue"])
        )

    # positive control: resetting a real, provisioned setting succeeds
    reset_resp = ssm.reset_service_setting(SettingId=real_setting_id)
    status = reset_resp["ServiceSetting"]["Status"]
    assert status == "Default", f"expected positive-control reset to report Status=Default, got {status!r}"

    # break exactly one thing: reset a setting id that was never provisioned
    fake_setting_id = (
        f"arn:aws:ssm:{ctx.region}:{account_id}:servicesetting/ssm/parameter-store/"
        "sim2real-not-a-real-setting"
    )
    code, message = _client_error(lambda: ssm.reset_service_setting(SettingId=fake_setting_id))
    assert code == "ServiceSettingNotFound", (
        f"expected ResetServiceSetting on an unprovisioned setting id to raise "
        f"ServiceSettingNotFound, got {code!r}"
    )
    assert message == "", f"unexpected message {message!r}"

    # effect absent: the fake setting still can't be read back either (nothing was created)
    code2, message2 = _client_error(lambda: ssm.get_service_setting(SettingId=fake_setting_id))
    assert code2 == "ServiceSettingNotFound", (
        f"expected GetServiceSetting on the same unprovisioned id to also raise "
        f"ServiceSettingNotFound (nothing should have been created), got {code2!r}"
    )
    assert message2 == "", f"unexpected message {message2!r}"


def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
