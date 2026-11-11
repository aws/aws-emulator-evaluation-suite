"""start-flow-missing-source-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "start-flow-missing-source-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediaconnect"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFlow with neither Source nor Sources fails BadRequestException with the exact message and
    creates no flow, while a request with a source creates a flow that starts and reaches ACTIVE."""
    mc = ctx.client("mediaconnect")
    sourceless_name = ctx.unique_name("sim2real-mc-flow-nosrc-")

    def _cleanup_leak(result: dict) -> None:
        leaked_arn = result["Flow"]["FlowArn"]
        ctx.on_cleanup(lambda: _stop_and_delete(mc, leaked_arn))

    code, message = _client_error(lambda: mc.create_flow(Name=sourceless_name), _cleanup_leak)
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected = (
        "Validation failed:\nYour request contains more than one field for source (source and "
        "sources). Update your request to include only one of these fields."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no flow with this name was created
    matching = [f for f in _list_all_flows(mc) if f["Name"] == sourceless_name]
    assert matching == [], f"expected no flow named {sourceless_name!r}, found {matching!r}"

    # positive control: a flow with a real source creates and starts fine
    sourced_arn = mc.create_flow(
        Name=ctx.unique_name("sim2real-mc-flow-src-"),
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
    )["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: _stop_and_delete(mc, sourced_arn))
    mc.start_flow(FlowArn=sourced_arn)
    status = _poll_status(mc, sourced_arn, {"ACTIVE"}, 120)
    assert status == "ACTIVE", f"expected sourced flow to reach ACTIVE, last status={status!r}"


def _list_all_flows(mc) -> list:
    flows = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = mc.list_flows(**kwargs)
        flows.extend(resp.get("Flows", []))
        token = resp.get("NextToken")
        if not token:
            break
    return flows


def _poll_status(mc, flow_arn: str, terminal: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Status"]
        if last in terminal:
            return last
        time.sleep(3)
    raise AssertionError(f"flow never reached {terminal}, last status={last}")


def _stop_and_delete(mc, flow_arn: str) -> None:
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


def _client_error(fn, on_unexpected_success=None):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        return err.get("Code"), err.get("Message")
    if on_unexpected_success is not None:
        on_unexpected_success(result)
    raise AssertionError(f"expected rejection but call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
