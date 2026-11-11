"""take-router-input-routes-and-unroutes."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "take-router-input-routes-and-unroutes"
GROUP = "state-machine"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TakeRouterInput routes a router input to an output (RoutedState UNROUTED -> ROUTED, input
    RoutedOutputs 1), and calling it again without RouterInputArn unroutes it (UNROUTED, RoutedOutputs 0)."""
    mc = ctx.client("mediaconnect")
    ni_arn = _create_public_network_interface(ctx, mc)

    input_arn = _create_router_input(ctx, mc, ni_arn)
    output_arn = _create_router_output(ctx, mc, ni_arn)

    initial_state = mc.get_router_output(Arn=output_arn)["RouterOutput"]["RoutedState"]
    assert initial_state == "UNROUTED", f"expected UNROUTED before any take, got {initial_state}"

    mc.take_router_input(RouterOutputArn=output_arn, RouterInputArn=input_arn)
    routed_state = _poll_routed_state(mc, output_arn, {"ROUTED", "ERROR"}, timeout_s=90)
    assert routed_state == "ROUTED", f"expected ROUTED after take, got {routed_state}"
    out = mc.get_router_output(Arn=output_arn)["RouterOutput"]
    assert out["RoutedInputArn"] == input_arn, (
        f"expected RoutedInputArn={input_arn}, got {out.get('RoutedInputArn')}"
    )
    routed_outputs = mc.get_router_input(Arn=input_arn)["RouterInput"]["RoutedOutputs"]
    assert routed_outputs == 1, f"expected input RoutedOutputs=1 after take, got {routed_outputs}"

    mc.take_router_input(RouterOutputArn=output_arn)
    routed_state = _poll_routed_state(mc, output_arn, {"UNROUTED", "ERROR"}, timeout_s=90)
    assert routed_state == "UNROUTED", f"expected UNROUTED after untake, got {routed_state}"
    routed_outputs = mc.get_router_input(Arn=input_arn)["RouterInput"]["RoutedOutputs"]
    assert routed_outputs == 0, f"expected input RoutedOutputs=0 after untake, got {routed_outputs}"


def _create_public_network_interface(ctx, mc) -> str:
    ni_resp = mc.create_router_network_interface(
        Name=ctx.unique_name("sim2real-mc-rni-"),
        Configuration={"Public": {"AllowRules": [{"Cidr": "203.0.113.0/24"}]}},
        Tags={"sim2real-check": CHECK},
    )
    ni_arn = ni_resp["RouterNetworkInterface"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: mc.delete_router_network_interface(Arn=ni_arn)))
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        state = mc.get_router_network_interface(Arn=ni_arn)["RouterNetworkInterface"]["State"]
        if state == "ACTIVE":
            return ni_arn
        time.sleep(3)
    raise AssertionError("router network interface never reached ACTIVE")


def _create_router_input(ctx, mc, ni_arn: str) -> str:
    resp = mc.create_router_input(
        Name=ctx.unique_name("sim2real-mc-rin-"),
        Configuration={
            "Standard": {
                "NetworkInterfaceArn": ni_arn,
                "Protocol": "RTP",
                "ProtocolConfiguration": {"Rtp": {"Port": 5001}},
            }
        },
        MaximumBitrate=10_000_000,
        RoutingScope="REGIONAL",
        Tier="INPUT_20",
        Tags={"sim2real-check": CHECK},
    )
    arn = resp["RouterInput"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: mc.delete_router_input(Arn=arn)))
    _poll_state(mc.get_router_input, arn, "RouterInput", {"STANDBY", "ERROR"}, 120)
    return arn


def _create_router_output(ctx, mc, ni_arn: str) -> str:
    resp = mc.create_router_output(
        Name=ctx.unique_name("sim2real-mc-rout-"),
        Configuration={
            "Standard": {
                "NetworkInterfaceArn": ni_arn,
                "Protocol": "RTP",
                "ProtocolConfiguration": {
                    "Rtp": {"DestinationAddress": "10.0.0.6", "DestinationPort": 5001}
                },
            }
        },
        MaximumBitrate=10_000_000,
        RoutingScope="REGIONAL",
        Tier="OUTPUT_20",
        Tags={"sim2real-check": CHECK},
    )
    arn = resp["RouterOutput"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: mc.delete_router_output(Arn=arn)))
    _poll_state(mc.get_router_output, arn, "RouterOutput", {"STANDBY", "ERROR"}, 120)
    return arn


def _poll_state(getter, arn: str, key: str, terminal: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = getter(Arn=arn)[key]["State"]
        if last in terminal:
            return last
        time.sleep(3)
    raise AssertionError(f"{key} never reached {terminal}, last state={last}")


def _poll_routed_state(mc, output_arn: str, terminal: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = mc.get_router_output(Arn=output_arn)["RouterOutput"]["RoutedState"]
        if last in terminal:
            return last
        time.sleep(2)
    raise AssertionError(f"routed state never reached {terminal}, last={last}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
