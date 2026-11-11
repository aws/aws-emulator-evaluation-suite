"""op-contract-allocateIpamPoolCidr-b."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-allocateIpamPoolCidr-b"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """AllocateIpamPoolCidr carves a CIDR that GetIpamPoolAllocations lists, then with DryRun fails
    DryRunOperation and on a well-formed nonexistent pool id fails InvalidIpamPoolId.NotFound, each
    with its exact message and a RequestId.
    """
    ec2 = ctx.client("ec2")

    # The check creates its own IPAM; IPAMs per Region is 1 by default, so CreateIpam retries
    # ResourceLimitExceeded while another IPAM finishes deleting.
    ipam_id = _create_ipam_with_retry(
        ctx,
        ec2,
        description=ctx.unique_name("sim2real-ipam-"),
        region=ctx.region,
        timeout_s=650,
        interval_s=2,
    )
    ctx.on_cleanup(lambda: _delete_ipam(ec2, ipam_id))
    ipam = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=90,
        interval_s=3,
    )
    scope_id = ipam["PrivateDefaultScopeId"]

    # The pool range is drawn at random inside the check's own IPAM scope.
    octet = random.randint(16, 250)
    pool_cidr = f"10.{octet}.0.0/16"

    pool_id = ec2.create_ipam_pool(
        IpamScopeId=scope_id,
        AddressFamily="ipv4",
        Locale=ctx.region,
        TagSpecifications=[
            {
                "ResourceType": "ipam-pool",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-pool-")}],
            }
        ],
    )["IpamPool"]["IpamPoolId"]
    ctx.on_cleanup(lambda: _delete_pool(ec2, pool_id))
    _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]["State"],
        lambda s: s == "create-complete",
        timeout_s=90,
        interval_s=3,
    )

    ec2.provision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=pool_cidr)
    ctx.on_cleanup(lambda: _deprovision_pool_cidr(ec2, pool_id, pool_cidr))
    _poll_until(
        lambda: _pool_cidr_state(ec2, pool_id, pool_cidr),
        lambda s: s == "provisioned",
        timeout_s=90,
        interval_s=3,
    )

    # --- positive control: AllocateIpamPoolCidr really succeeds on a real, provisioned pool ---
    alloc = ec2.allocate_ipam_pool_cidr(IpamPoolId=pool_id, NetmaskLength=28)["IpamPoolAllocation"]
    allocation_id = alloc["IpamPoolAllocationId"]
    allocation_cidr = alloc["Cidr"]
    ctx.on_cleanup(lambda: _release_allocation(ec2, pool_id, allocation_id, allocation_cidr))

    # AllocateIpamPoolCidr's own response can precede the allocation's visibility via
    # GetIpamPoolAllocations (eventual consistency); poll until it is, rather than trusting the
    # first read.
    def _visible_allocation():
        try:
            return ec2.get_ipam_pool_allocations(
                IpamPoolId=pool_id, IpamPoolAllocationId=allocation_id
            )["IpamPoolAllocations"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidIpamPoolAllocationId.NotFound":
                return None
            raise

    visible = _poll_until(_visible_allocation, lambda v: v, timeout_s=60, interval_s=3)
    assert len(visible) == 1 and visible[0]["Cidr"] == allocation_cidr, (
        f"expected the real allocation visible via an independent read, got {visible!r}"
    )

    # --- error boundary: a well-formed but nonexistent pool id ---
    fake_pool_id = "ipam-pool-0fedcba987654321f"

    info = _client_error_info(
        lambda: ec2.allocate_ipam_pool_cidr(
            IpamPoolId=fake_pool_id, NetmaskLength=28, DryRun=True
        )
    )
    assert info["code"] == "DryRunOperation", f"expected DryRunOperation, got {info['code']!r}"
    assert info["message"] == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {info['message']!r}"
    )
    assert info["request_id"], "expected a RequestId in ResponseMetadata"

    info2 = _client_error_info(
        lambda: ec2.allocate_ipam_pool_cidr(IpamPoolId=fake_pool_id, NetmaskLength=28)
    )
    assert info2["code"] == "InvalidIpamPoolId.NotFound", (
        f"expected InvalidIpamPoolId.NotFound, got {info2['code']!r}"
    )
    expected = f"The ipam-pool ID '{fake_pool_id}' does not exist"
    assert info2["message"] == expected, (
        f"expected message {expected!r}, got {info2['message']!r}"
    )
    assert info2["request_id"], "expected a RequestId in ResponseMetadata"


def _client_error_info(fn):
    """Call fn(); return its error code/message/RequestId. An unexpected SUCCESS raises,
    because a target ACCEPTING input real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {
            "code": err["Code"],
            "message": err.get("Message"),
            "request_id": exc.response.get("ResponseMetadata", {}).get("RequestId"),
        }
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _create_ipam_with_retry(ctx, ec2, *, description, region, timeout_s=650.0, interval_s=2.0):
    """CreateIpam, retrying ResourceLimitExceeded (the per-Region IPAM quota) to a deadline capped
    by ctx.time_left()."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
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


def _pool_cidr_state(ec2, pool_id, cidr):
    for c in ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id)["IpamPoolCidrs"]:
        if c["Cidr"] == cidr:
            return c["State"]
    return "not-found"


def _release_allocation(ec2, pool_id, allocation_id, allocation_cidr):
    try:
        ec2.release_ipam_pool_allocation(
            IpamPoolId=pool_id, IpamPoolAllocationId=allocation_id, Cidr=allocation_cidr
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidIpamPoolId.NotFound":
            raise


def _deprovision_pool_cidr(ec2, pool_id, cidr):
    try:
        ec2.deprovision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=cidr)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidIpamPoolId.NotFound":
            raise


_POOL_TEARDOWN_S = 300.0


def _delete_pool(ec2, pool_id):
    """Delete the pool. DeprovisionIpamPoolCidr completes asynchronously, and DeleteIpamPool answers
    DependencyViolation while a CIDR is still provisioned, so that answer is retried every 2 s
    within one deadline."""
    deadline = time.monotonic() + _POOL_TEARDOWN_S
    while True:
        try:
            ec2.delete_ipam_pool(IpamPoolId=pool_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidIpamPoolId.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_ipam(ec2, ipam_id):
    try:
        ec2.delete_ipam(IpamId=ipam_id, Cascade=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidIpamId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
