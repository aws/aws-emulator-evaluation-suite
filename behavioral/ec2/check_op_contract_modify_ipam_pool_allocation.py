"""op-contract-modify-ipam-pool-allocation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-modify-ipam-pool-allocation"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ModifyIpamPoolAllocation updates an allocation's description, echoed and read back; an unknown
    allocation id fails with InvalidIpamPoolAllocationId.NotFound and its exact message."""
    ec2 = ctx.client("ec2")
    _ipam_id, private_scope_id, _public_scope_id = _create_ipam(ctx, ec2)
    pool_id = _create_ipam_pool(ctx, ec2, private_scope_id)
    _provision_pool_cidr(ctx, ec2, pool_id, "10.123.0.0/16")

    allocation = ec2.allocate_ipam_pool_cidr(
        IpamPoolId=pool_id, NetmaskLength=24, Description="initial-alloc"
    )["IpamPoolAllocation"]
    allocation_id = allocation["IpamPoolAllocationId"]

    # allocate_ipam_pool_cidr can return before the allocation is visible/modifiable
    # via ModifyIpamPoolAllocation due to eventual consistency; poll until it is.
    def _allocation_visible():
        try:
            ec2.modify_ipam_pool_allocation(IpamPoolAllocationId=allocation_id, Description="initial-alloc")
            return True
        except Exception as exc:  # botocore.exceptions.ClientError
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "InvalidIpamPoolAllocationId.NotFound":
                return False
            raise

    visible = _poll_until(lambda: _allocation_visible(), lambda ok: ok, timeout_s=60, interval_s=3)
    assert visible, "allocation never became visible/modifiable via ModifyIpamPoolAllocation within 60s"

    # success path
    resp = ec2.modify_ipam_pool_allocation(
        IpamPoolAllocationId=allocation_id, Description="updated-by-sim2real"
    )
    updated = resp["IpamPoolAllocation"]
    assert updated["Description"] == "updated-by-sim2real", (
        f"expected Description 'updated-by-sim2real', got {updated['Description']!r}"
    )
    assert updated["IpamPoolAllocationId"] == allocation_id, (
        f"expected IpamPoolAllocationId {allocation_id!r}, got {updated['IpamPoolAllocationId']!r}"
    )

    described = ec2.get_ipam_pool_allocations(
        IpamPoolId=pool_id, IpamPoolAllocationId=allocation_id
    )["IpamPoolAllocations"][0]
    assert described["Description"] == "updated-by-sim2real", (
        f"expected independent read to reflect 'updated-by-sim2real', got {described['Description']!r}"
    )

    # error boundary: unknown allocation id
    code, message = _error(
        lambda: ec2.modify_ipam_pool_allocation(
            IpamPoolAllocationId="ipam-pool-alloc-00000000000000000", Description="x"
        )
    )
    assert code == "InvalidIpamPoolAllocationId.NotFound", f"expected NotFound code, got {code}"
    assert message == "The ipam-pool-allocation ID 'ipam-pool-alloc-00000000000000000' does not exist", message


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _create_ipam(ctx, ec2):
    # IPAMs are an extremely low, account-wide quota (one per account per region), and unlike a
    # per-check TGW or VPC there's no reason to expect a slot to free up on its own -- so reuse any
    # existing, fully-created IPAM (ours or a concurrently running check's) instead of
    # racing everyone else's CreateIpam for the account's single slot.
    reused = _reusable_ipam(ec2)
    if reused is not None:
        return reused["IpamId"], reused["PrivateDefaultScopeId"], reused["PublicDefaultScopeId"]

    ipam_id = _create_ipam_with_retry(ec2, description=ctx.unique_name("sim2real-behav-ipam-"), region=ctx.region)

    def _cleanup():
        try:
            ec2.delete_ipam(IpamId=ipam_id, Cascade=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidIpamId.NotFound":
                raise

    ctx.on_cleanup(_cleanup)

    ipam = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=90,
        interval_s=3,
    )
    assert ipam is not None and ipam["State"] == "create-complete", "IPAM never reached create-complete"
    return ipam_id, ipam["PrivateDefaultScopeId"], ipam["PublicDefaultScopeId"]


def _reusable_ipam(ec2):
    paginator = ec2.get_paginator("describe_ipams")
    for page in paginator.paginate():
        for ipam in page["Ipams"]:
            if ipam["State"] == "create-complete":
                return ipam
    return None


def _create_ipam_with_retry(ec2, *, description, region, timeout_s=650.0, interval_s=20.0):
    """Retry CreateIpam across ResourceLimitExceeded: the account's single-IPAM quota can be held
    transiently by a concurrently running check, which is contention, not a real capacity
    shortfall."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_ipam(
                Description=description,
                OperatingRegions=[{"RegionName": region}],
                TagSpecifications=[
                    {"ResourceType": "ipam", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
                ],
            )["Ipam"]["IpamId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceLimitExceeded" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_ipam_pool(ctx, ec2, scope_id):
    pool = ec2.create_ipam_pool(
        IpamScopeId=scope_id,
        AddressFamily="ipv4",
        Locale=ctx.region,
        Description=ctx.unique_name("sim2real-behav-pool-"),
        TagSpecifications=[
            {"ResourceType": "ipam-pool", "Tags": [{"Key": "sim2real-check", "Value": CHECK}]}
        ],
    )["IpamPool"]
    pool_id = pool["IpamPoolId"]

    def _cleanup():
        try:
            ec2.delete_ipam_pool(IpamPoolId=pool_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidIpamPoolId.NotFound":
                raise

    ctx.on_cleanup(_cleanup)

    pool = _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0],
        lambda p: p["State"] == "create-complete",
        timeout_s=90,
        interval_s=3,
    )
    assert pool is not None and pool["State"] == "create-complete", "IPAM pool never reached create-complete"
    return pool_id


def _provision_pool_cidr(ctx, ec2, pool_id, cidr):
    ec2.provision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=cidr)
    provisioned = _poll_until(
        lambda: next(
            (
                c
                for c in ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id)["IpamPoolCidrs"]
                if c["Cidr"] == cidr
            ),
            None,
        ),
        lambda c: c is not None and c["State"] == "provisioned",
        timeout_s=90,
        interval_s=3,
    )
    assert provisioned is not None and provisioned["State"] == "provisioned", "pool CIDR never provisioned"
    return cidr


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
