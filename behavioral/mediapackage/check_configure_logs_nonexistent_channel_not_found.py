"""configure-logs-nonexistent-channel-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "configure-logs-nonexistent-channel-not-found"
GROUP = "overly-permissive"
SERVICES = ["mediapackage"]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ConfigureLogs on an Id that names no channel fails NotFoundException with the exact message, while
    ConfigureLogs on a real channel sets EgressAccessLogs to the given log group, as DescribeChannel
    confirms."""
    mp = ctx.client("mediapackage")

    bogus_id = ctx.unique_name("sim2real-mp-missing-")
    code, message = _error_code(
        lambda: mp.configure_logs(Id=bogus_id, EgressAccessLogs={"LogGroupName": "/aws/x"})
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code!r}"
    expected_message = f"channel with id={bogus_id} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    real_id = ctx.unique_name("sim2real-mp-real-")
    mp.create_channel(Id=real_id, Tags={"purpose": "behavioral-check"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=real_id))

    log_group = "/aws/MediaPackage/" + ctx.unique_name("sim2real-mp-log-")
    configured = mp.configure_logs(Id=real_id, EgressAccessLogs={"LogGroupName": log_group})
    assert configured["EgressAccessLogs"]["LogGroupName"] == log_group, (
        f"expected {log_group!r}, got {configured['EgressAccessLogs'].get('LogGroupName')!r}"
    )

    described = mp.describe_channel(Id=real_id)
    assert described["EgressAccessLogs"]["LogGroupName"] == log_group, (
        f"expected {log_group!r}, got {described['EgressAccessLogs'].get('LogGroupName')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
