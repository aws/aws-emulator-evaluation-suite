"""flow-output-status-toggle."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "flow-output-status-toggle"
GROUP = "state-machine"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddFlowOutputs creates an ENABLED output by default; UpdateFlowOutput can
    disable and re-enable it, and DescribeFlow reflects the persisted OutputStatus."""
    mc = ctx.client("mediaconnect")
    name = ctx.unique_name("sim2real-mc-flow-")
    flow_arn = mc.create_flow(
        Name=name,
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
        FlowTags={"sim2real-check": "flow-output-status-toggle"},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: mc.delete_flow(FlowArn=flow_arn))

    add_resp = mc.add_flow_outputs(
        FlowArn=flow_arn,
        Outputs=[{"Name": "out1", "Protocol": "rtp-fec", "Destination": "10.0.0.5", "Port": 5000}],
    )
    output_arn = add_resp["Outputs"][0]["OutputArn"]
    got = add_resp["Outputs"][0]["OutputStatus"]
    assert got == "ENABLED", f"expected a newly added output to default to ENABLED, got {got!r}"

    mc.update_flow_output(FlowArn=flow_arn, OutputArn=output_arn, OutputStatus="DISABLED")
    status = _get_output_status(mc, flow_arn, output_arn)
    assert status == "DISABLED", f"expected DISABLED after UpdateFlowOutput, DescribeFlow showed {status!r}"

    mc.update_flow_output(FlowArn=flow_arn, OutputArn=output_arn, OutputStatus="ENABLED")
    status = _get_output_status(mc, flow_arn, output_arn)
    assert status == "ENABLED", f"expected ENABLED after re-enabling, DescribeFlow showed {status!r}"


def _get_output_status(mc, flow_arn: str, output_arn: str) -> str:
    flow = mc.describe_flow(FlowArn=flow_arn)["Flow"]
    for out in flow["Outputs"]:
        if out["OutputArn"] == output_arn:
            return out["OutputStatus"]
    raise AssertionError("output not found on flow")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
