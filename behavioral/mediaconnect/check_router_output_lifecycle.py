"""router-output-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "router-output-lifecycle"
GROUP = "state-machine"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new RouterOutput settles to STANDBY, StartRouterOutput drives it to ACTIVE and
    StopRouterOutput back to STANDBY; once deleted, the output and its network interface
    read as NotFoundException and starting the dead output fails NotFoundException."""
    mc = ctx.client("mediaconnect")
    ni_arn = _create_public_network_interface(ctx, mc)

    resp = mc.create_router_output(
        Name=ctx.unique_name("sim2real-mc-rout-"),
        Configuration={
            "Standard": {
                "NetworkInterfaceArn": ni_arn,
                "Protocol": "RTP",
                "ProtocolConfiguration": {
                    "Rtp": {"DestinationAddress": "10.0.0.5", "DestinationPort": 5000}
                },
            }
        },
        MaximumBitrate=10_000_000,
        RoutingScope="REGIONAL",
        Tier="OUTPUT_20",
        Tags={"sim2real": CHECK},
    )
    output_arn = resp["RouterOutput"]["Arn"]
    ctx.on_cleanup(lambda: _delete_router_output(mc, output_arn))

    state = _poll_router_output_state(mc, output_arn, {"STANDBY", "ERROR"}, timeout_s=120)
    assert state == "STANDBY", f"expected STANDBY after create, got {state}"

    mc.start_router_output(Arn=output_arn)
    state = _poll_router_output_state(mc, output_arn, {"ACTIVE", "ERROR"}, timeout_s=120)
    assert state == "ACTIVE", f"expected ACTIVE after start, got {state}"

    mc.stop_router_output(Arn=output_arn)
    state = _poll_router_output_state(mc, output_arn, {"STANDBY", "ERROR"}, timeout_s=120)
    assert state == "STANDBY", f"expected STANDBY after stop, got {state}"

    mc.delete_router_output(Arn=output_arn)
    _poll_router_output_gone(mc, output_arn, timeout_s=120)
    code, message = _client_error(lambda: mc.start_router_output(Arn=output_arn))
    assert code == "NotFoundException", (
        f"expected NotFoundException starting a deleted router output, got {code}"
    )
    expected = f"Not found: {output_arn}"
    assert message == expected, (
        f"expected message {expected!r} starting a deleted router output, got {message!r}"
    )

    mc.delete_router_network_interface(Arn=ni_arn)
    _poll_network_interface_gone(mc, ni_arn, timeout_s=120)


# ===== helpers =====
def _create_public_network_interface(ctx, mc) -> str:
    ni_resp = mc.create_router_network_interface(
        Name=ctx.unique_name("sim2real-mc-rni-"),
        Configuration={"Public": {"AllowRules": [{"Cidr": "203.0.113.0/24"}]}},
        Tags={"sim2real": CHECK},
    )
    ni_arn = ni_resp["RouterNetworkInterface"]["Arn"]
    ctx.on_cleanup(lambda: _delete_network_interface(mc, ni_arn))
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        state = mc.get_router_network_interface(Arn=ni_arn)["RouterNetworkInterface"]["State"]
        if state == "ACTIVE":
            return ni_arn
        time.sleep(3)
    raise AssertionError("router network interface never reached ACTIVE")


def _delete_network_interface(mc, ni_arn: str) -> None:
    try:
        mc.delete_router_network_interface(Arn=ni_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _delete_router_output(mc, output_arn: str) -> None:
    """Stop a running output, wait for STANDBY, then delete it; only NotFoundException means gone."""
    deadline = time.monotonic() + 120
    while True:
        try:
            state = mc.get_router_output(Arn=output_arn)["RouterOutput"]["State"]
            if state == "ACTIVE":
                mc.stop_router_output(Arn=output_arn)
            elif state in ("STANDBY", "ERROR"):
                mc.delete_router_output(Arn=output_arn)
                return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"router output {output_arn} still {state} after 120 s; cannot delete it")
        time.sleep(2)


def _poll_router_output_state(mc, output_arn: str, terminal: set, timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = mc.get_router_output(Arn=output_arn)["RouterOutput"]["State"]
        if last in terminal:
            return last
        time.sleep(3)
    raise AssertionError(f"router output never reached {terminal}, last state={last}")


def _poll_router_output_gone(mc, output_arn: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        try:
            last_state = mc.get_router_output(Arn=output_arn)["RouterOutput"]["State"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            raise AssertionError(f"expected NotFoundException reading deleted router output, got {code}")
        time.sleep(3)
    raise AssertionError(
        f"deleted router output never became not-found within {timeout_s}s; last state={last_state}"
    )


def _poll_network_interface_gone(mc, ni_arn: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        try:
            last_state = mc.get_router_network_interface(Arn=ni_arn)["RouterNetworkInterface"]["State"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            raise AssertionError(
                f"expected NotFoundException reading deleted network interface, got {code}"
            )
        time.sleep(3)
    raise AssertionError(
        f"deleted network interface never became not-found within {timeout_s}s; last state={last_state}"
    )


def _client_error(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected success
    raises: accepting a call AWS refuses is reported as such, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
