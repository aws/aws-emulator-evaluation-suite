"""configure-logs-sets-custom-log-group-names."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "configure-logs-sets-custom-log-group-names"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ConfigureLogs persists custom CloudWatch log group names for both egress and
    ingress access logging, and DescribeChannel reflects the exact configured names
    (not the service defaults)."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    mp.create_channel(Id=channel_id, Tags={"sim2real": "configure-logs-custom-names"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    before = mp.describe_channel(Id=channel_id)
    before_egress = before.get("EgressAccessLogs", {}).get("LogGroupName")
    before_ingress = before.get("IngressAccessLogs", {}).get("LogGroupName")
    assert not before_egress, f"expected no default egress log group, got {before_egress!r}"
    assert not before_ingress, f"expected no default ingress log group, got {before_ingress!r}"

    egress_group = "/aws/MediaPackage/" + ctx.unique_name("sim2real-mp-egress-")
    ingress_group = "/aws/MediaPackage/" + ctx.unique_name("sim2real-mp-ingress-")
    result = mp.configure_logs(
        Id=channel_id,
        EgressAccessLogs={"LogGroupName": egress_group},
        IngressAccessLogs={"LogGroupName": ingress_group},
    )
    result_egress = result["EgressAccessLogs"]["LogGroupName"]
    result_ingress = result["IngressAccessLogs"]["LogGroupName"]
    assert result_egress == egress_group, (
        f"expected egress log group {egress_group!r}, got {result_egress!r}"
    )
    assert result_ingress == ingress_group, (
        f"expected ingress log group {ingress_group!r}, got {result_ingress!r}"
    )

    described = mp.describe_channel(Id=channel_id)
    described_egress = described["EgressAccessLogs"]["LogGroupName"]
    described_ingress = described["IngressAccessLogs"]["LogGroupName"]
    assert described_egress == egress_group, (
        f"expected DescribeChannel to reflect egress log group {egress_group!r}, got {described_egress!r}"
    )
    assert described_ingress == ingress_group, (
        f"expected DescribeChannel to reflect ingress log group {ingress_group!r}, got {described_ingress!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
