"""create-gateway-duplicate-name-allowed."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-gateway-duplicate-name-allowed"
GROUP = "data-plane"
SERVICES = ["mediaconnect"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two gateways with the same Name coexist under distinct GatewayArns; deleting one settles it in
    GatewayState DELETED (still describable, and a repeated DeleteGateway succeeds) while the other keeps
    its ARN, Name and a non-DELETED state."""
    mc = ctx.client("mediaconnect")
    name = ctx.unique_name("sim2real-mc-gw-")
    _wait_for_gateway_quota_headroom(mc, needed=2, timeout_s=45)

    first_arn = _create_gateway_with_backoff(
        mc,
        timeout_s=45,
        Name=name,
        EgressCidrBlocks=["10.0.0.0/24"],
        Networks=[{"Name": "net1", "CidrBlock": "172.28.0.0/16"}],
    )["Gateway"]["GatewayArn"]
    ctx.on_cleanup(lambda: _safe(lambda: mc.delete_gateway(GatewayArn=first_arn)))

    second_arn = _create_gateway_with_backoff(
        mc,
        timeout_s=45,
        Name=name,
        EgressCidrBlocks=["10.0.1.0/24"],
        Networks=[{"Name": "net2", "CidrBlock": "172.29.0.0/16"}],
    )["Gateway"]["GatewayArn"]
    ctx.on_cleanup(lambda: _safe(lambda: mc.delete_gateway(GatewayArn=second_arn)))

    assert second_arn != first_arn, f"expected two distinct GatewayArns, got the same ARN twice: {first_arn}"

    # both gateways share the Name but are distinct resources by ARN
    # (list_gateways can lag briefly behind create_gateway -- poll for consistency)
    _poll_until(
        lambda: {g["GatewayArn"] for g in _list_all_gateways(mc) if g["Name"] == name},
        lambda arns: {first_arn, second_arn} <= arns,
        timeout_s=30,
        what=f"ListGateways to include both {first_arn!r} and {second_arn!r} for name {name!r}",
    )

    # deleting one does not affect the other. DeleteGateway is async: the target
    # moves DELETING -> DELETED and stays describable in DELETED state rather than
    # vanishing.
    _delete_gateway_with_retry(mc, first_arn, timeout_s=45)
    _poll_until(
        lambda: mc.describe_gateway(GatewayArn=first_arn)["Gateway"]["GatewayState"],
        lambda s: s == "DELETED",
        timeout_s=90,
        what=f"{first_arn!r} to settle in GatewayState DELETED after DeleteGateway",
    )

    # DeleteGateway is documented idempotent; repeating it against the DELETED
    # gateway must succeed again rather than raise NotFoundException/ConflictException
    # -- an unexpected raise here fails the check via the propagated ClientError.
    mc.delete_gateway(GatewayArn=first_arn)

    still_there = mc.describe_gateway(GatewayArn=second_arn)["Gateway"]
    assert still_there["GatewayArn"] == second_arn, f"expected surviving gateway ARN {second_arn!r}, got {still_there['GatewayArn']!r}"
    assert still_there["Name"] == name, f"expected surviving gateway Name {name!r} unchanged, got {still_there['Name']!r}"
    assert still_there["GatewayState"] != "DELETED", (
        f"expected surviving gateway {second_arn!r} to be unaffected by deleting {first_arn!r}, "
        f"got GatewayState={still_there['GatewayState']!r}"
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
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if len(_list_all_gateways(mc)) + needed <= 3:
            return
        time.sleep(5)


def _poll_until(getter, predicate, timeout_s: float, what: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = getter()
        if predicate(last):
            return last
        time.sleep(3)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {what}; last observed {last!r}")


def _create_gateway_with_backoff(mc, timeout_s: float = 150, **kwargs):
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


def _delete_gateway_with_retry(mc, gateway_arn: str, timeout_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            mc.delete_gateway(GatewayArn=gateway_arn)
            return
        except Exception as exc:
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
