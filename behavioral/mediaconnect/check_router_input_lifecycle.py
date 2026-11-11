"""router-input-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "router-input-lifecycle"
GROUP = "state-machine"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A RouterInput is created in CREATING then settles to STANDBY; StartRouterInput
    drives STANDBY->STARTING->ACTIVE and StopRouterInput drives ACTIVE->STOPPING->STANDBY."""
    mc = ctx.client("mediaconnect")
    ni_arn = _create_public_network_interface(ctx, mc)

    resp = mc.create_router_input(
        Name=ctx.unique_name("sim2real-mc-rin-"),
        Configuration={
            "Standard": {
                "NetworkInterfaceArn": ni_arn,
                "Protocol": "RTP",
                "ProtocolConfiguration": {"Rtp": {"Port": 5000}},
            }
        },
        MaximumBitrate=10_000_000,
        RoutingScope="REGIONAL",
        Tier="INPUT_20",
        Tags={"sim2real-check": CHECK},
    )
    input_arn = resp["RouterInput"]["Arn"]
    ctx.on_cleanup(lambda: _delete_router_input(mc, input_arn))

    state = _poll_router_input_state(mc, input_arn, {"STANDBY", "ERROR"}, timeout_s=120)
    assert state == "STANDBY", f"expected new router input to settle to STANDBY, got {state}"

    mc.start_router_input(Arn=input_arn)
    state = _poll_router_input_state(mc, input_arn, {"ACTIVE", "ERROR"}, timeout_s=120)
    assert state == "ACTIVE", f"expected StartRouterInput to drive state to ACTIVE, got {state}"

    mc.stop_router_input(Arn=input_arn)
    state = _poll_router_input_state(mc, input_arn, {"STANDBY", "ERROR"}, timeout_s=120)
    assert state == "STANDBY", f"expected StopRouterInput to drive state back to STANDBY, got {state}"


# ===== helpers =====
def _create_public_network_interface(ctx, mc) -> str:
    ni_resp = mc.create_router_network_interface(
        Name=ctx.unique_name("sim2real-mc-rni-"),
        Configuration={"Public": {"AllowRules": [{"Cidr": "203.0.113.0/24"}]}},
        Tags={"sim2real-check": CHECK},
    )
    ni_arn = ni_resp["RouterNetworkInterface"]["Arn"]
    ctx.on_cleanup(lambda: _delete_network_interface(mc, ni_arn))
    deadline = time.monotonic() + 120
    state = None
    while time.monotonic() < deadline:
        state = mc.get_router_network_interface(Arn=ni_arn)["RouterNetworkInterface"]["State"]
        if state == "ACTIVE":
            return ni_arn
        time.sleep(3)
    raise AssertionError(f"router network interface never reached ACTIVE, last state={state}")


def _delete_network_interface(mc, ni_arn: str) -> None:
    try:
        mc.delete_router_network_interface(Arn=ni_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_router_input(mc, input_arn: str) -> None:
    """Stop a running input, wait for STANDBY, then delete it; only NotFoundException means gone."""
    deadline = time.monotonic() + 120
    while True:
        try:
            state = mc.get_router_input(Arn=input_arn)["RouterInput"]["State"]
            if state == "ACTIVE":
                mc.stop_router_input(Arn=input_arn)
            elif state in ("STANDBY", "ERROR"):
                mc.delete_router_input(Arn=input_arn)
                return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"router input {input_arn} still {state} after 120 s; cannot delete it")
        time.sleep(2)


def _poll_router_input_state(mc, input_arn: str, terminal: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = mc.get_router_input(Arn=input_arn)["RouterInput"]["State"]
        if last in terminal:
            return last
        time.sleep(3)
    raise AssertionError(f"router input never reached {terminal}, last state={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
