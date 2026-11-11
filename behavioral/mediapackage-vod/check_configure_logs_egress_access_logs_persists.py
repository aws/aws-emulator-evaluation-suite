"""configure-logs-egress-access-logs-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "configure-logs-egress-access-logs-persists"
GROUP = "state"
SERVICES = ["mediapackage-vod"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ConfigureLogs persists the EgressAccessLogs log-group configuration on the packaging group,
    visible on a subsequent DescribePackagingGroup."""
    mpv = ctx.client("mediapackage-vod")
    logs = ctx.client("logs")

    group_id = ctx.unique_name("sim2real-mpvod-group-")
    mpv.create_packaging_group(Id=group_id, Tags={"env": "sim2real", "owner": "behavioral-suite"})
    ctx.on_cleanup(lambda: mpv.delete_packaging_group(Id=group_id))

    log_group_name = f"/aws/MediaPackage/{group_id}"
    logs.create_log_group(
        logGroupName=log_group_name, tags={"env": "sim2real", "owner": "behavioral-suite"}
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    configured = mpv.configure_logs(
        Id=group_id, EgressAccessLogs={"LogGroupName": log_group_name}
    )
    assert configured["EgressAccessLogs"]["LogGroupName"] == log_group_name, (
        f"expected ConfigureLogs response to echo log group {log_group_name!r}, "
        f"got {configured['EgressAccessLogs']}"
    )
    assert configured["Id"] == group_id, f"expected Id {group_id!r}, got {configured['Id']!r}"

    described = mpv.describe_packaging_group(Id=group_id)
    assert described["EgressAccessLogs"]["LogGroupName"] == log_group_name, (
        f"expected DescribePackagingGroup to persist log group {log_group_name!r}, "
        f"got {described.get('EgressAccessLogs')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
