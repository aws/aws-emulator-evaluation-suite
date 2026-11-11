"""op-contract-modify-verified-access-instance-logging-configuration."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-modify-verified-access-instance-logging-configuration"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVerifiedAccessInstanceLoggingConfiguration turns CloudWatch Logs delivery on (with the log
    group) and then off on a fresh instance, each confirmed by an independent describe; an unknown
    instance id fails with InvalidVerifiedAccessInstanceId.NotFound and its exact message."""
    ec2 = ctx.client("ec2")
    logs = ctx.client("logs")

    name = ctx.unique_name("vai-logging-")
    vai_id = ec2.create_verified_access_instance(
        TagSpecifications=[{"ResourceType": "verified-access-instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )["VerifiedAccessInstance"]["VerifiedAccessInstanceId"]
    ctx.on_cleanup(lambda: ec2.delete_verified_access_instance(VerifiedAccessInstanceId=vai_id))

    log_group_name = ctx.unique_name("/simparity/vai-logs-")
    logs.create_log_group(logGroupName=log_group_name, tags={"Name": name})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    baseline = ec2.describe_verified_access_instance_logging_configurations(
        VerifiedAccessInstanceIds=[vai_id]
    )["LoggingConfigurations"][0]["AccessLogs"]["CloudWatchLogs"]
    assert baseline["Enabled"] is False, f"fresh instance should start with CloudWatch Logs disabled: {baseline}"

    enabled_access_logs = {
        "CloudWatchLogs": {"Enabled": True, "LogGroup": log_group_name},
        "IncludeTrustContext": False,
        "LogVersion": "ocsf-1.0.0-rc.2",
    }
    resp = ec2.modify_verified_access_instance_logging_configuration(
        VerifiedAccessInstanceId=vai_id, AccessLogs=enabled_access_logs
    )
    cfg = resp["LoggingConfiguration"]["AccessLogs"]["CloudWatchLogs"]
    assert cfg["Enabled"] is True, f"expected CloudWatchLogs enabled in response: {cfg}"
    assert cfg["LogGroup"] == log_group_name, f"expected log group {log_group_name!r}, got {cfg}"

    described = ec2.describe_verified_access_instance_logging_configurations(
        VerifiedAccessInstanceIds=[vai_id]
    )["LoggingConfigurations"][0]["AccessLogs"]["CloudWatchLogs"]
    assert described["Enabled"] is True, f"independent read did not see enabled state: {described}"
    assert described["LogGroup"] == log_group_name, f"independent read log group mismatch: {described}"

    disabled_access_logs = {
        "CloudWatchLogs": {"Enabled": False},
        "IncludeTrustContext": False,
        "LogVersion": "ocsf-1.0.0-rc.2",
    }
    resp = ec2.modify_verified_access_instance_logging_configuration(
        VerifiedAccessInstanceId=vai_id, AccessLogs=disabled_access_logs
    )
    cfg = resp["LoggingConfiguration"]["AccessLogs"]["CloudWatchLogs"]
    assert cfg["Enabled"] is False, f"expected CloudWatchLogs disabled in response: {cfg}"

    described = ec2.describe_verified_access_instance_logging_configurations(
        VerifiedAccessInstanceIds=[vai_id]
    )["LoggingConfigurations"][0]["AccessLogs"]["CloudWatchLogs"]
    assert described["Enabled"] is False, f"independent read did not see disabled state: {described}"

    code, code_msg = _client_error(
        lambda: ec2.modify_verified_access_instance_logging_configuration(
            VerifiedAccessInstanceId="vai-00000000000000000", AccessLogs=disabled_access_logs
        )
    )
    assert code == "InvalidVerifiedAccessInstanceId.NotFound", f"unexpected error code: {code}"
    assert code_msg == "The verified-access-instance ID 'vai-00000000000000000' does not exist", code_msg


def _client_error(fn):
    """Call fn() and return its (code, message). An unexpected success raises, because an
    emulator accepting input real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
