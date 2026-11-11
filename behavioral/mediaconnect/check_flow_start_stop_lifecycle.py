"""flow-start-stop-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "flow-start-stop-lifecycle"
GROUP = "state-machine"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateFlow starts in STANDBY; StartFlow brings the flow to ACTIVE and StopFlow back to
    STANDBY, each polled with DescribeFlow to its stable state."""
    mc = ctx.client("mediaconnect")
    name = ctx.unique_name("sim2real-mc-flow-")
    resp = mc.create_flow(
        Name=name,
        Source={"Name": "source1", "Protocol": "rtp", "WhitelistCidr": "203.0.113.0/24"},
        FlowTags={"env": "sim2real-test", "team": "media"},
    )
    flow_arn = resp["Flow"]["FlowArn"]
    ctx.on_cleanup(lambda: _delete_flow(mc, flow_arn))
    assert resp["Flow"]["Status"] == "STANDBY", f"expected STANDBY on create, got {resp['Flow']['Status']}"

    mc.start_flow(FlowArn=flow_arn)
    status = _poll_until_status(ctx, mc, flow_arn, "ACTIVE", {"STANDBY", "STARTING"}, timeout_s=120)
    assert status == "ACTIVE", f"expected ACTIVE after StartFlow, last status={status}"

    mc.stop_flow(FlowArn=flow_arn)
    status = _poll_until_status(ctx, mc, flow_arn, "STANDBY", {"ACTIVE", "STOPPING"}, timeout_s=120)
    assert status == "STANDBY", f"expected STANDBY after StopFlow, last status={status}"


# ===== helpers =====
def _delete_flow(mc, flow_arn: str) -> None:
    """Stop a running flow, wait for STANDBY within the 60 s cleanup budget, then delete it; only
    NotFoundException means gone."""
    deadline = time.monotonic() + 55
    while True:
        try:
            status = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Status"]
            if status == "ACTIVE":
                mc.stop_flow(FlowArn=flow_arn)
            elif status in ("STANDBY", "ERROR"):
                mc.delete_flow(FlowArn=flow_arn)
                return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"flow {flow_arn} still {status} after 55 s; cannot delete it")
        time.sleep(2)


def _poll_until_status(
    ctx, mc, flow_arn: str, stable: str, transient: set, timeout_s: float
) -> str:
    """Poll DescribeFlow every 2 s until the flow reaches ``stable``; a status outside it and its
    ``transient`` states (the one it leaves and the one it passes through) ends the poll, so the
    caller's assert names it."""
    left = ctx.time_left()
    # Stop 5 s before the runner's budget, so the caller's assert, not the runner, reports a stuck flow.
    wait_s = timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0))
    deadline = time.monotonic() + wait_s
    while True:
        last = mc.describe_flow(FlowArn=flow_arn)["Flow"]["Status"]
        if last == stable or last not in transient or time.monotonic() >= deadline:
            return last
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
