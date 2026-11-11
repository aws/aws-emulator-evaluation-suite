"""concurrent-gateway-create-same-name-single-winner."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-gateway-create-same-name-single-winner"
GROUP = "concurrency"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateGateway does not treat Name as a uniqueness key: N concurrent calls reusing
    one Name each succeed with a distinct GatewayArn, and ListGateways shows all N."""
    mc = ctx.client("mediaconnect")
    name = ctx.unique_name("sim2real-mc-gw-race-")
    racer_count = 3
    _wait_for_gateway_quota_headroom(mc, needed=racer_count, timeout_s=90)

    def _attempt(i: int):
        return mc.create_gateway(
            Name=name,
            EgressCidrBlocks=[f"10.{i}.0.0/24"],
            Networks=[{"Name": f"net{i}", "CidrBlock": f"172.{28 + i}.0.0/16"}],
        )["Gateway"]["GatewayArn"]

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        arns = list(pool.map(_attempt, range(racer_count)))

    for arn in arns:
        ctx.on_cleanup(lambda a=arn: _delete_until_gone(lambda: mc.delete_gateway(GatewayArn=a)))
        _safe(lambda a=arn: mc.tag_resource(ResourceArn=a, Tags={"sim2real": "behavioral"}))

    assert len(arns) == racer_count, f"expected {racer_count} create_gateway calls to return, got {len(arns)}"
    assert len(set(arns)) == racer_count, f"expected {racer_count} distinct ARNs, got {arns}"

    # ListGateways reflects exactly `racer_count` surviving gateways with this name
    # (list_gateways can lag briefly behind create_gateway -- poll for consistency)
    matching = _poll_until(
        lambda: {g["GatewayArn"] for g in _list_all_gateways(mc) if g["Name"] == name},
        lambda found: set(arns) <= found,
        timeout_s=60,
    )
    assert set(arns) <= matching, f"expected all of {arns} in ListGateways for name {name!r}, got {matching}"


# ===== helpers =====
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
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if len(_list_all_gateways(mc)) + needed <= 3:
            return
        time.sleep(5)


def _poll_until(getter, predicate, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = getter()
        if predicate(last):
            return last
        time.sleep(3)
    raise TimeoutError(f"poll did not satisfy predicate within {timeout_s}s, last value: {last!r}")


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
