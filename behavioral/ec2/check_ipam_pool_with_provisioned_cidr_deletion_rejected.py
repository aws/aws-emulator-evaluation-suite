"""ipam-pool-with-provisioned-cidr-deletion-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ipam-pool-with-provisioned-cidr-deletion-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DeleteIpamPool rejects a pool that still has a CIDR provisioned to it (no Cascade):
    you must deprovision/deallocate first. This is a state-conflict boundary distinct from
    a bogus-id lookup."""
    ec2 = ctx.client("ec2")

    ipam = _create_ipam_with_capacity(
        ctx, ec2,
        Description=ctx.unique_name("sim2real-ipam-poolreject-"),
        OperatingRegions=[{"RegionName": ctx.region}],
    )
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    ipam = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=60,
    )
    private_scope_id = ipam["PrivateDefaultScopeId"]

    pool = ec2.create_ipam_pool(
        IpamScopeId=private_scope_id,
        AddressFamily="ipv4",
        Locale=ctx.region,
    )["IpamPool"]
    pool_id = pool["IpamPoolId"]

    _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0],
        lambda p: p["State"] == "create-complete",
        timeout_s=60,
    )

    ec2.provision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr="10.99.0.0/16")
    _poll_until(
        lambda: [
            c
            for c in ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id)["IpamPoolCidrs"]
            if c["Cidr"] == "10.99.0.0/16"
        ],
        lambda cidrs: bool(cidrs) and cidrs[0]["State"] == "provisioned",
        timeout_s=60,
    )

    # A provisioned CIDR alone does not reliably block DeleteIpamPool; an active allocation
    # does, so one is allocated out of the provisioned CIDR.
    allocation = ec2.allocate_ipam_pool_cidr(IpamPoolId=pool_id, NetmaskLength=28)[
        "IpamPoolAllocation"
    ]
    allocation_id = allocation["IpamPoolAllocationId"]
    allocation_cidr = allocation["Cidr"]

    # deleting a pool that still has a provisioned CIDR (with an allocation carved out of it)
    # is rejected synchronously with DependencyViolation, and the pool stays create-complete.
    code, message = _error(lambda: ec2.delete_ipam_pool(IpamPoolId=pool_id))
    assert code == "DependencyViolation", f"expected DependencyViolation, got {code!r}"
    assert message == (
        f"The specified action is not valid for {pool_id}. "
        "There are one or more pool cidrs provisioned in the pool."
    ), f"unexpected DependencyViolation message {message!r}"

    # the pool must still exist, still holding its provisioned CIDR and the allocation
    still_there = ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]
    assert still_there["State"] == "create-complete", (
        f"expected the pool to survive the rejected delete in create-complete, "
        f"got state={still_there['State']!r}"
    )
    cidrs = ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id)["IpamPoolCidrs"]
    assert any(c["Cidr"] == "10.99.0.0/16" and c["State"] == "provisioned" for c in cidrs), (
        f"expected the provisioned CIDR 10.99.0.0/16 to still be present and provisioned, "
        f"got cidrs={cidrs!r}"
    )
    # read the pool's allocations unfiltered: an IpamPoolAllocationId filter can answer
    # InvalidIpamPoolAllocationId.NotFound for an allocation the pool lists.
    allocations = _poll_until(
        lambda: ec2.get_ipam_pool_allocations(IpamPoolId=pool_id)["IpamPoolAllocations"],
        lambda allocs: any(a["IpamPoolAllocationId"] == allocation_id for a in allocs),
        timeout_s=60,
    )
    assert any(a["IpamPoolAllocationId"] == allocation_id for a in allocations), (
        f"expected allocation {allocation_id} to still be present after the rejected "
        f"delete, got allocations={allocations!r}"
    )

    # restore: the allocation caused the rejection, so releasing it and deprovisioning the CIDR
    # lets the identical DeleteIpamPool call succeed.
    ec2.release_ipam_pool_allocation(
        IpamPoolId=pool_id, IpamPoolAllocationId=allocation_id, Cidr=allocation_cidr
    )
    allocations_after_release = _poll_until(
        lambda: [
            a
            for a in ec2.get_ipam_pool_allocations(IpamPoolId=pool_id)["IpamPoolAllocations"]
            if a["IpamPoolAllocationId"] == allocation_id
        ],
        lambda allocs: allocs == [],
        timeout_s=60,
    )
    assert allocations_after_release == [], (
        f"expected the allocation to be gone after release, got {allocations_after_release!r}"
    )

    ec2.deprovision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr="10.99.0.0/16")
    _poll_until(
        lambda: _cidr_state(ec2, pool_id, "10.99.0.0/16"),
        lambda s: s in ("deprovisioned", None),
        timeout_s=60,
    )

    # the pool settles in create-complete before a fresh DeleteIpamPool is accepted.
    _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]["State"],
        lambda s: s == "create-complete",
        timeout_s=60,
    )

    ec2.delete_ipam_pool(IpamPoolId=pool_id)
    gone = _poll_until(
        lambda: _describe_pools_tolerant(ec2, pool_id),
        lambda pools: (not pools) or pools[0]["State"] == "delete-complete",
        timeout_s=120,
    )
    assert not gone or gone[0]["State"] == "delete-complete", (
        f"expected the identical DeleteIpamPool call to succeed once the allocation and "
        f"CIDR are gone, got {gone!r}"
    )

    # a second delete on the now-gone pool must fail with the specific not-found error,
    # not silently succeed.
    second_delete_code, second_delete_message = _error(
        lambda: ec2.delete_ipam_pool(IpamPoolId=pool_id)
    )
    assert second_delete_code == "InvalidIpamPoolId.NotFound", (
        f"expected a double-delete on the now-gone pool to fail with "
        f"InvalidIpamPoolId.NotFound, got {second_delete_code!r}"
    )
    assert second_delete_message == f"The ipam-pool ID '{pool_id}' does not exist", (
        f"unexpected InvalidIpamPoolId.NotFound message {second_delete_message!r}"
    )


def _create_ipam_with_capacity(ctx, ec2, **kwargs):
    """CreateIpam, retrying ONLY the per-Region quota refusal (IPAMs per Region is 1 by default)
    while another IPAM finishes deleting, every 2 s to a deadline capped by ctx.time_left()."""
    left = ctx.time_left()
    cap = 480.0 if left is None else min(480.0, left)
    deadline = time.monotonic() + cap
    while True:
        try:
            return ec2.create_ipam(**kwargs)["Ipam"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceLimitExceeded":
                raise
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"no IPAM slot freed within {cap:.0f} s: "
                    f"{exc.response['Error'].get('Message')!r}"
                ) from exc
            time.sleep(2)


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator answering a call real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _cidr_state(ec2, pool_id, cidr):
    for c in ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id)["IpamPoolCidrs"]:
        if c["Cidr"] == cidr:
            return c["State"]
    return None


def _describe_pools_tolerant(ec2, pool_id):
    # once the pool is truly gone, DescribeIpamPools raises NotFound instead of
    # returning an empty list - treat that as "deleted" for polling purposes.
    try:
        return ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidIpamPoolId.NotFound":
            return []
        raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
