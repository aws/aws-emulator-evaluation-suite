"""take-router-input-routing-scope-mismatch-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "take-router-input-routing-scope-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediaconnect"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TakeRouterInput with an ARN-shaped RouterInputArn that resolves to no router input fails
    BadRequestException with the exact message and leaves the output UNROUTED with no RoutedInputArn,
    while a real router input routes the same output to ROUTED."""
    mc = ctx.client("mediaconnect")
    ni_arn = _create_public_network_interface(ctx, mc)
    output_arn = _create_router_output(ctx, mc, ni_arn, port=5100)
    bogus_input_arn = output_arn.replace(":router-output:", ":router-input:") + "-does-not-exist"

    code, message = _client_error(
        lambda: mc.take_router_input(RouterOutputArn=output_arn, RouterInputArn=bogus_input_arn)
    )
    assert code == "BadRequestException", f"expected BadRequestException, got {code!r}"
    expected = f"Bad request: Invalid ARN: {bogus_input_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: output remains UNROUTED
    out = mc.get_router_output(Arn=output_arn)["RouterOutput"]
    assert out["RoutedState"] == "UNROUTED", f"expected UNROUTED, got {out['RoutedState']!r}"
    assert "RoutedInputArn" not in out, f"expected no RoutedInputArn, got {out.get('RoutedInputArn')!r}"

    # positive control: a real router input routes fine to the same output
    real_input_arn = _create_router_input(ctx, mc, ni_arn, port=5102)
    mc.take_router_input(RouterOutputArn=output_arn, RouterInputArn=real_input_arn)
    routed_state = _poll_routed_state(mc, output_arn, {"ROUTED", "ERROR"}, 90)
    assert routed_state == "ROUTED", f"expected ROUTED, got {routed_state!r}"


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


def _create_router_input(ctx, mc, ni_arn: str, port: int) -> str:
    resp = mc.create_router_input(
        Name=ctx.unique_name("sim2real-mc-rin-"),
        Configuration={
            "Standard": {
                "NetworkInterfaceArn": ni_arn,
                "Protocol": "RTP",
                "ProtocolConfiguration": {"Rtp": {"Port": port}},
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


def _create_router_output(ctx, mc, ni_arn: str, port: int) -> str:
    resp = mc.create_router_output(
        Name=ctx.unique_name("sim2real-mc-rout-"),
        Configuration={
            "Standard": {
                "NetworkInterfaceArn": ni_arn,
                "Protocol": "RTP",
                "ProtocolConfiguration": {
                    "Rtp": {"DestinationAddress": "10.0.0.7", "DestinationPort": port}
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


def _client_error(fn):
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
