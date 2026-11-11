"""configure-logs-sets-log-group-names."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "configure-logs-sets-log-group-names"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ConfigureLogs persists custom CloudWatch log group names for both egress and
    ingress access logs, visible via both the call's response and DescribeChannel."""
    mp = ctx.client("mediapackage")

    cid = ctx.unique_name("sim2real-mp-logs-")
    mp.create_channel(Id=cid, Tags={"purpose": "behavioral-check"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid))

    egress_group = f"/aws/MediaPackage/{ctx.unique_name('sim2real-mp-egress-')}"
    ingress_group = f"/aws/MediaPackage/{ctx.unique_name('sim2real-mp-ingress-')}"

    configured = mp.configure_logs(
        Id=cid,
        EgressAccessLogs={"LogGroupName": egress_group},
        IngressAccessLogs={"LogGroupName": ingress_group},
    )
    actual_egress = configured["EgressAccessLogs"]["LogGroupName"]
    assert actual_egress == egress_group, (
        f"ConfigureLogs response egress log group: expected {egress_group!r}, got {actual_egress!r}"
    )
    actual_ingress = configured["IngressAccessLogs"]["LogGroupName"]
    assert actual_ingress == ingress_group, (
        f"ConfigureLogs response ingress log group: expected {ingress_group!r}, got {actual_ingress!r}"
    )

    described = mp.describe_channel(Id=cid)
    described_egress = described["EgressAccessLogs"]["LogGroupName"]
    assert described_egress == egress_group, (
        f"DescribeChannel egress log group: expected {egress_group!r}, got {described_egress!r}"
    )
    described_ingress = described["IngressAccessLogs"]["LogGroupName"]
    assert described_ingress == ingress_group, (
        f"DescribeChannel ingress log group: expected {ingress_group!r}, got {described_ingress!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
