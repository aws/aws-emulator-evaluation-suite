"""describe-flow-source-metadata-not-yet-available."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "describe-flow-source-metadata-not-yet-available"
GROUP = "error-semantics"
SERVICES = ["mediaconnect"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeFlowSourceMetadata fails BadRequestException with the exact message while a new flow is
    STANDBY (DescribeFlow answers for it), and the same call succeeds with TransportMediaInfo once the
    flow is ACTIVE, with no media sent: it is gated on flow status, not ingest."""
    mc = ctx.client("mediaconnect")
    flow_arn = mc.create_flow(
        Name=ctx.unique_name("sim2real-mc-flow-"),
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: _stop_and_delete(mc, flow_arn))

    code, message = _client_error(lambda: mc.describe_flow_source_metadata(FlowArn=flow_arn))
    assert code == "BadRequestException", (
        f"expected BadRequestException on a STANDBY flow, got {code!r}"
    )
    expected = "Bad request: The flow must be in ACTIVE state to perform this action"
    assert message == expected, f"expected message {expected!r} on a STANDBY flow, got {message!r}"

    # positive control: the flow itself is fully describable while STANDBY
    described = mc.describe_flow(FlowArn=flow_arn)["Flow"]
    assert described["FlowArn"] == flow_arn
    assert described["Status"] == "STANDBY", f"expected STANDBY, got {described['Status']!r}"

    # restore: start the flow, and demand the IDENTICAL call succeeds
    mc.start_flow(FlowArn=flow_arn)
    status = _poll_status(mc, flow_arn, {"ACTIVE"}, timeout_s=120)
    assert status == "ACTIVE", f"flow never reached ACTIVE, last status={status!r}"

    metadata = mc.describe_flow_source_metadata(FlowArn=flow_arn)
    assert metadata["FlowArn"] == flow_arn
    assert "TransportMediaInfo" in metadata, (
        f"expected TransportMediaInfo once ACTIVE, got keys={sorted(metadata.keys())}"
    )


def _client_error(fn):
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_status(mc, flow_arn, terminal, timeout_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Status"]
        if last in terminal:
            return last
        time.sleep(3)
    raise AssertionError(f"flow never reached {terminal}, last status={last!r}")


def _stop_and_delete(mc, flow_arn):
    try:
        mc.stop_flow(FlowArn=flow_arn)
    except (mc.exceptions.BadRequestException, mc.exceptions.NotFoundException):
        pass
    for _ in range(150):
        try:
            status = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Status"]
        except mc.exceptions.NotFoundException:
            return
        if status == "STANDBY":
            break
        if status == "ACTIVE":
            # A stop sent while the flow was still STARTING is refused; send it again.
            try:
                mc.stop_flow(FlowArn=flow_arn)
            except mc.exceptions.BadRequestException:
                pass
        time.sleep(2)
    try:
        mc.delete_flow(FlowArn=flow_arn)
    except mc.exceptions.NotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
