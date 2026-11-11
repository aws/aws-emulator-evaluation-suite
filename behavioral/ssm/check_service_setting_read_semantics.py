"""service-setting-read-semantics."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "service-setting-read-semantics"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetServiceSetting returns a status-bearing setting whose ARN carries this
    account and region and whose last modifier is always reported; unknown ids are
    rejected."""

    ssm = ctx.client("ssm")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    def _error_code(fn):
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError("expected a ClientError but the call succeeded")

    setting_id = "/ssm/parameter-store/high-throughput-enabled"
    expected_arn = f"arn:aws:ssm:{ctx.region}:{account_id}:servicesetting{setting_id}"
    setting = ssm.get_service_setting(SettingId=setting_id)["ServiceSetting"]
    assert setting["SettingId"] == setting_id, setting
    assert setting["ARN"] == expected_arn, setting
    assert setting["Status"] in ("Default", "Customized", "PendingUpdate"), setting
    assert setting["SettingValue"] in ("true", "false"), setting
    assert setting.get("LastModifiedDate") is not None, setting

    # Real AWS populates LastModifiedUser even for a setting that was never customized
    # ("System"), which contradicts the docs' "populated only if overwritten" claim. The
    # setting is account-wide and other runs reset it, so who modified it last is theirs.
    assert setting.get("LastModifiedUser"), setting

    code, message = _error_code(
        lambda: ssm.get_service_setting(SettingId="/ssm/probe/does-not-exist")
    )
    assert code == "ServiceSettingNotFound", code
    assert message == "", message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
