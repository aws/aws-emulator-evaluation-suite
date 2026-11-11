"""concurrent-modify-ipam-resource-cidr-conflicting-updates."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "concurrent-modify-ipam-resource-cidr-conflicting-updates"
GROUP = "concurrency"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """Two simultaneous ModifyIpamResourceCidr calls on one resource CIDR, Monitored True and False, settle to
    ManagementState managed or ignored, and a further call for that state reports it back.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-ipamrace-")


    ipam = ec2.create_ipam(
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    scope_id = ipam["PrivateDefaultScopeId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))
    _poll_until(lambda: _ipam_state(ec2, ipam_id), lambda s: s == "create-complete", timeout_s=120, interval_s=3)

    pool_id = ec2.create_ipam_pool(
        IpamScopeId=scope_id,
        AddressFamily="ipv4",
        Locale=ctx.region,
        TagSpecifications=[{"ResourceType": "ipam-pool", "Tags": [{"Key": "Name", "Value": name}]}],
    )["IpamPool"]["IpamPoolId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam_pool(IpamPoolId=pool_id))
    _poll_until(lambda: _pool_state(ec2, pool_id), lambda s: s == "create-complete", timeout_s=120, interval_s=3)

    ec2.provision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr="10.222.0.0/16")
    _poll_until(
        lambda: _pool_cidr_state(ec2, pool_id, "10.222.0.0/16"),
        lambda s: s == "provisioned",
        timeout_s=120,
        interval_s=3,
    )

    vpc_id = ec2.create_vpc(
        Ipv4IpamPoolId=pool_id,
        Ipv4NetmaskLength=24,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    # IPAM tracks a pool-allocated CIDR through its background reconciliation, so this polls to a
    # bounded deadline rather than assuming it is visible at once.
    resource = _poll_for_resource_cidr(ec2, scope_id, vpc_id, timeout_s=900.0)

    assert resource is not None, "IPAM never surfaced the pool-allocated VPC's resource CIDR in the private scope"

    barrier = threading.Barrier(2)

    def _modify(monitored: bool):
        barrier.wait(timeout=30)
        return _call(
            lambda: ec2.modify_ipam_resource_cidr(
                ResourceId=vpc_id,
                ResourceCidr=resource["ResourceCidr"],
                ResourceRegion=resource["ResourceRegion"],
                CurrentIpamScopeId=scope_id,
                Monitored=monitored,
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_true = pool.submit(_modify, True)
        fut_false = pool.submit(_modify, False)
        result_true = fut_true.result()
        result_false = fut_false.result()

    def _final_state():
        found = _find_resource_cidr(ec2, scope_id, vpc_id)
        return found["ManagementState"] if found is not None else None

    final_state = _poll_until(
        _final_state, lambda s: s in ("managed", "ignored"), timeout_s=60, interval_s=3
    )
    assert final_state in ("managed", "ignored"), (
        f"expected the racing updates to converge to a single valid ManagementState, got {final_state!r} "
        f"(results were True-call={result_true!r} False-call={result_false!r})"
    )

    # Confirm the record is not stuck mid-transition: re-asserting the
    # observed state round-trips cleanly and reports the same state back.
    confirm_monitored = final_state == "managed"
    confirmed = ec2.modify_ipam_resource_cidr(
        ResourceId=vpc_id,
        ResourceCidr=resource["ResourceCidr"],
        ResourceRegion=resource["ResourceRegion"],
        CurrentIpamScopeId=scope_id,
        Monitored=confirm_monitored,
    )["IpamResourceCidr"]
    assert confirmed["ManagementState"] == final_state


def _call(fn: Callable[[], Any]):
    from botocore.exceptions import ClientError

    try:
        return ("ok", fn())
    except ClientError as exc:
        return ("error", exc.response["Error"]["Code"])


def _ipam_state(ec2, ipam_id: str):
    return ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0]["State"]


def _pool_state(ec2, pool_id: str):
    return ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]["State"]


def _pool_cidr_state(ec2, pool_id: str, cidr: str):
    for c in ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id)["IpamPoolCidrs"]:
        if c["Cidr"] == cidr:
            return c["State"]
    return None


def _find_resource_cidr(ec2, scope_id: str, vpc_id: str):
    resp = ec2.get_ipam_resource_cidrs(IpamScopeId=scope_id, ResourceId=vpc_id)
    for r in resp.get("IpamResourceCidrs", []):
        if r.get("ResourceId") == vpc_id:
            return r
    return None


def _poll_for_resource_cidr(ec2, scope_id: str, vpc_id: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        found = _find_resource_cidr(ec2, scope_id, vpc_id)
        if found is not None:
            return found
        time.sleep(5)
    return None


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

