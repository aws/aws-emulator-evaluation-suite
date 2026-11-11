"""bridge-add-remove-source-and-output."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bridge-add-remove-source-and-output"
GROUP = "data-plane"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddBridgeSources attaches a second source that DescribeBridge reflects, and
    RemoveBridgeSource detaches it so only the original source remains (an ingress
    bridge's outputs are managed by the flows that use it, so outputs are not exercised)."""
    mc = ctx.client("mediaconnect")
    _wait_for_gateway_quota_headroom(mc, needed=1, timeout_s=60)
    gateway_arn = _create_gateway_with_backoff(
        mc,
        Name=ctx.unique_name("sim2real-mc-gw-"),
        EgressCidrBlocks=["10.0.0.0/24"],
        Networks=[{"Name": "net1", "CidrBlock": "172.28.0.0/16"}],
    )["Gateway"]["GatewayArn"]
    ctx.on_cleanup(lambda: _delete_until_gone(lambda: mc.delete_gateway(GatewayArn=gateway_arn)))
    _safe(lambda: mc.tag_resource(ResourceArn=gateway_arn, Tags={"sim2real": "bridge-add-remove-source-and-output"}))
    _wait_for_gateway_active(mc, gateway_arn, timeout_s=60)

    bridge_arn = mc.create_bridge(
        Name=ctx.unique_name("sim2real-mc-bridge-"),
        PlacementArn=gateway_arn,
        IngressGatewayBridge={"MaxBitrate": 100_000_000, "MaxOutputs": 2},
        Sources=[
            {
                "NetworkSource": {
                    "Name": "src1",
                    "NetworkName": "net1",
                    "MulticastIp": "228.10.10.10",
                    "Port": 6000,
                    "Protocol": "udp",
                }
            }
        ],
    )["Bridge"]["BridgeArn"]
    ctx.on_cleanup(lambda: _delete_until_gone(lambda: mc.delete_bridge(BridgeArn=bridge_arn), 60))
    _safe(lambda: mc.tag_resource(ResourceArn=bridge_arn, Tags={"sim2real": "bridge-add-remove-source-and-output"}))

    # source failover must be enabled before a second source can be added; MERGE mode rejects UDP
    # sources ("UDP protocol may not be used with failover MERGE mode"), so FAILOVER is what applies
    # here — confirmed against real AWS, not assumed.
    mc.update_bridge(
        BridgeArn=bridge_arn,
        SourceFailoverConfig={"State": "ENABLED", "FailoverMode": "FAILOVER"},
    )

    mc.add_bridge_sources(
        BridgeArn=bridge_arn,
        Sources=[
            {
                "NetworkSource": {
                    "Name": "src2",
                    "NetworkName": "net1",
                    "MulticastIp": "228.10.10.11",
                    "Port": 6001,
                    "Protocol": "udp",
                }
            }
        ],
    )

    described = mc.describe_bridge(BridgeArn=bridge_arn)["Bridge"]
    names = {_source_name(s) for s in described["Sources"]}
    assert names == {"src1", "src2"}, f"expected sources {{'src1', 'src2'}} after AddBridgeSources, got {names}"

    mc.remove_bridge_source(BridgeArn=bridge_arn, SourceName="src2")

    described = mc.describe_bridge(BridgeArn=bridge_arn)["Bridge"]
    names = {_source_name(s) for s in described["Sources"]}
    assert names == {"src1"}, f"expected only {{'src1'}} after RemoveBridgeSource('src2'), got {names}"


# ===== helpers =====
def _source_name(s: dict) -> str:
    return s.get("Name") or s.get("NetworkSource", {}).get("Name") or s.get("FlowSource", {}).get("Name")


def _list_all_gateways(mc) -> list:
    gateways = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = mc.list_gateways(**kwargs)
        gateways.extend(resp.get("Gateways", []))
        token = resp.get("NextToken")
        if not token:
            break
    return gateways


def _wait_for_gateway_quota_headroom(mc, needed: int, timeout_s: float) -> None:
    """The account-wide MediaConnect gateway quota is very low (default 3 per
    Region), and sibling checks running concurrently also create gateways. Wait
    for enough headroom rather than racing straight into a transient 420."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if len(_list_all_gateways(mc)) + needed <= 3:
            return
        time.sleep(5)


def _wait_for_gateway_active(mc, gateway_arn: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = mc.describe_gateway(GatewayArn=gateway_arn)["Gateway"]["GatewayState"]
        if last == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"gateway never reached ACTIVE, last state={last}")


def _create_gateway_with_backoff(mc, timeout_s: float = 60, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return mc.create_gateway(**kwargs)
        except Exception as exc:  # botocore.exceptions.ClientError
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code in ("420", "CreateGateway420Exception") or "exceeded" in str(exc).lower():
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise last_exc


def _delete_until_gone(fn, timeout_s: float = 120) -> None:
    """Teardown: retry ConflictException (a dependent resource is still being released)
    every 2 s to a deadline; NotFoundException means already gone; anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe(fn) -> None:
    try:
        fn()
    except Exception:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
