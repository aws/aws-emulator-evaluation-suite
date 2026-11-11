"""bridge-create-and-delete-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "bridge-create-and-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created bridge reports its placement and source; once STANDBY, UpdateBridge takes effect.
    DeleteBridge leaves it describable as DELETED, and the same UpdateBridge then fails
    BadRequestException with the exact STANDBY message.
    """
    mc = ctx.client("mediaconnect")
    _wait_for_gateway_quota_headroom(mc, needed=1, timeout_s=60)
    gateway_arn = _create_gateway_with_backoff(
        mc,
        Name=ctx.unique_name("sim2real-mc-gw-"),
        EgressCidrBlocks=["10.0.0.0/24"],
        Networks=[{"Name": "net1", "CidrBlock": "172.28.0.0/16"}],
    )["Gateway"]["GatewayArn"]
    ctx.on_cleanup(lambda: _safe(lambda: mc.delete_gateway(GatewayArn=gateway_arn)))
    _wait_for_gateway_active(mc, gateway_arn, timeout_s=60)

    resp = mc.create_bridge(
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
    )
    bridge = resp["Bridge"]
    bridge_arn = bridge["BridgeArn"]
    assert bridge["BridgeState"] in ("CREATING", "STANDBY", "DEPLOYING"), (
        f"expected a non-terminal BridgeState right after create, got {bridge['BridgeState']!r}"
    )
    assert bridge["PlacementArn"] == gateway_arn, (
        f"expected PlacementArn {gateway_arn!r}, got {bridge['PlacementArn']!r}"
    )

    described = mc.describe_bridge(BridgeArn=bridge_arn)["Bridge"]
    described_source = described["Sources"][0]
    source_name = described_source.get("Name") or described_source.get("NetworkSource", {}).get("Name")
    assert source_name == "src1", f"expected source name 'src1', got {source_name!r}"

    def _update():
        mc.update_bridge(
            BridgeArn=bridge_arn,
            SourceFailoverConfig={"State": "ENABLED", "FailoverMode": "FAILOVER"},
        )

    # UpdateBridge is accepted only in STANDBY (its own BadRequest message below), and CreateBridge
    # may return a transitional state: wait for STANDBY before the positive control.
    _poll_until(
        lambda: mc.describe_bridge(BridgeArn=bridge_arn)["Bridge"]["BridgeState"],
        lambda s: s == "STANDBY",
        timeout_s=120,
        budget_s=_budget_s(ctx, 120),
    )
    _update()  # positive control: the same mutation succeeds on the live bridge
    described = _poll_until(
        lambda: mc.describe_bridge(BridgeArn=bridge_arn)["Bridge"],
        lambda b: b.get("SourceFailoverConfig", {}).get("State") == "ENABLED",
        timeout_s=60,
        budget_s=_budget_s(ctx, 60),
    )
    failover_state = described.get("SourceFailoverConfig", {}).get("State")
    assert failover_state == "ENABLED", f"expected UpdateBridge to take effect, got SourceFailoverConfig.State={failover_state!r}"

    _delete_bridge_with_retry(mc, bridge_arn, timeout_s=60)

    state = _poll_until(
        lambda: mc.describe_bridge(BridgeArn=bridge_arn)["Bridge"]["BridgeState"],
        lambda s: s == "DELETED",
        timeout_s=45,
    )
    assert state == "DELETED", f"expected terminal BridgeState DELETED after delete, got {state!r}"

    # DescribeBridge does not raise NotFoundException after DeleteBridge on real AWS -- the bridge
    # is a persistent tombstone, not a removed resource. Two independent reads confirm the terminal
    # state does not revert, and the identical UpdateBridge call that succeeded above is now
    # rejected, proving the bridge is unusable even though it is still describable.
    for _ in range(2):
        state = mc.describe_bridge(BridgeArn=bridge_arn)["Bridge"]["BridgeState"]
        assert state == "DELETED", f"expected DELETED to persist, got {state!r}"

    mutate_code, mutate_message = _client_error(_update)
    assert mutate_code == "BadRequestException", (
        f"expected UpdateBridge on a deleted bridge to be rejected with BadRequestException, got {mutate_code!r}"
    )
    expected = "Validation failed:\nYou cannot update a bridge unless it is in STANDBY."
    assert mutate_message == expected, (
        f"expected UpdateBridge on a deleted bridge to be rejected with {expected!r}, got {mutate_message!r}"
    )


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


def _delete_bridge_with_retry(mc, bridge_arn: str, timeout_s: float) -> None:
    """DeleteBridge can be rejected with ConflictException/BadRequestException
    while the bridge is still mid-transition (e.g. CREATING); retry until it's
    accepted."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            mc.delete_bridge(BridgeArn=bridge_arn)
            return
        except Exception as exc:
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        fn()
    except Exception as exc:  # botocore.exceptions.ClientError
        err = getattr(exc, "response", {}).get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected UpdateBridge on a deleted bridge to be rejected, but it succeeded")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(getter, predicate, timeout_s: float, budget_s=None):
    start = time.monotonic()
    stop = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    last = None
    while time.monotonic() < stop:
        last = getter()
        if predicate(last):
            return last
        time.sleep(3)
    if budget_s is not None and budget_s < timeout_s:
        raise TimeoutError(
            f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
            f"{timeout_s}s wait ended (last={last!r}); not graded"
        )
    raise AssertionError(f"timed out after {timeout_s}s waiting for predicate, last value={last!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
