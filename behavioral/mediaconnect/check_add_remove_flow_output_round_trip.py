"""add-remove-flow-output-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "add-remove-flow-output-round-trip"
GROUP = "data-plane"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddFlowOutputs adds an output DescribeFlow lists, RemoveFlowOutput removes it from the list, and a
    further UpdateFlowOutput on the removed OutputArn fails NotFoundException with the exact message."""
    mc = ctx.client("mediaconnect")
    flow_arn = mc.create_flow(
        Name=ctx.unique_name("sim2real-mc-flow-"),
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
        FlowTags={"sim2real-check": CHECK},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: mc.delete_flow(FlowArn=flow_arn))

    add_resp = mc.add_flow_outputs(
        FlowArn=flow_arn,
        Outputs=[{"Name": "out1", "Protocol": "rtp-fec", "Destination": "10.0.0.5", "Port": 5000}],
    )
    output_arn = add_resp["Outputs"][0]["OutputArn"]

    arns = {o["OutputArn"] for o in mc.describe_flow(FlowArn=flow_arn)["Flow"]["Outputs"]}
    assert output_arn in arns, f"expected {output_arn} in DescribeFlow outputs, got {arns}"

    mc.remove_flow_output(FlowArn=flow_arn, OutputArn=output_arn)

    arns = {o["OutputArn"] for o in mc.describe_flow(FlowArn=flow_arn)["Flow"]["Outputs"]}
    assert output_arn not in arns, f"expected {output_arn} removed from DescribeFlow outputs, still present in {arns}"

    code, message = _client_error(
        lambda: mc.update_flow_output(FlowArn=flow_arn, OutputArn=output_arn, OutputStatus="DISABLED")
    )
    assert code == "NotFoundException", f"expected NotFoundException mutating a removed output, got {code}"
    expected = f"Not found: {output_arn}"
    assert message == expected, f"expected message {expected!r} mutating a removed output, got {message!r}"


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        if err.get("Code") is None:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call against the removed output to raise, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
