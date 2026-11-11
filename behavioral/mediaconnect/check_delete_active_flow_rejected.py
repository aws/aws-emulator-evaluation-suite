"""delete-active-flow-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-active-flow-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediaconnect"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteFlow on a flow that is still ACTIVE is rejected with BadRequestException;
    the flow is left fully intact (still describable, still ACTIVE). The positive
    control in this same file shows that stopping the flow first lets delete succeed."""
    mc = ctx.client("mediaconnect")
    flow_arn = mc.create_flow(
        Name=ctx.unique_name("sim2real-mc-flow-"),
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: _safe_delete(mc, flow_arn))
    mc.tag_resource(ResourceArn=flow_arn, Tags={"sim2real-check": CHECK})

    mc.start_flow(FlowArn=flow_arn)
    status = _poll_status(mc, flow_arn, {"ACTIVE"}, 120)
    assert status == "ACTIVE", f"flow never reached ACTIVE before the delete attempt, last={status!r}"

    code, message = _client_error(lambda: mc.delete_flow(FlowArn=flow_arn))
    assert code == "BadRequestException", f"expected BadRequestException deleting an ACTIVE flow, got {code!r}"
    expected = "Bad request: Flow must be in STANDBY in order for DELETE to be invoked."
    assert message == expected, f"expected message {expected!r} deleting an ACTIVE flow, got {message!r}"

    # effect absent: the flow is untouched and still ACTIVE
    described = mc.describe_flow(FlowArn=flow_arn)["Flow"]
    assert described["Status"] == "ACTIVE", f"flow status changed after a rejected delete, now {described['Status']!r}"
    assert described["FlowArn"] == flow_arn, f"describe_flow returned a different flow: {described['FlowArn']!r}"

    # positive control: stop first, then delete succeeds
    mc.stop_flow(FlowArn=flow_arn)
    _poll_status(mc, flow_arn, {"STANDBY"}, 120)
    mc.delete_flow(FlowArn=flow_arn)
    # deletion is asynchronous -- poll for the flow to actually disappear
    code, message = _poll_for_not_found(mc, flow_arn, 120)
    assert code == "NotFoundException", f"flow still describable {120}s after delete, last code={code!r}"
    expected_gone = f"Not found: {flow_arn}"
    assert message == expected_gone, f"expected message {expected_gone!r} describing a deleted flow, got {message!r}"

    # gone means unusable: a mutation on the dead id must fail the same way
    mutate_code, mutate_message = _client_error(lambda: mc.stop_flow(FlowArn=flow_arn))
    assert mutate_code == "NotFoundException", (
        f"stop_flow on a deleted flow did not raise NotFoundException, got {mutate_code!r}"
    )
    assert mutate_message == expected_gone, (
        f"expected message {expected_gone!r} stopping a deleted flow, got {mutate_message!r}"
    )


def _poll_for_not_found(mc, flow_arn: str, timeout_s: float):
    """Poll DescribeFlow until it raises; return that error's (code, message), or the
    last (code, message) seen when the budget runs out (None, None while still describable)."""
    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        try:
            mc.describe_flow(FlowArn=flow_arn)
            last = (None, None)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            last = (err.get("Code"), err.get("Message"))
            if last[0] == "NotFoundException":
                return last
        time.sleep(3)
    return last


def _poll_status(mc, flow_arn: str, terminal: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Status"]
        if last in terminal:
            return last
        time.sleep(3)
    raise AssertionError(f"flow never reached {terminal}, last status={last}")


def _client_error(fn):
    """Call fn(); return the AWS (code, message) on failure. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe_delete(mc, flow_arn: str) -> None:
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
