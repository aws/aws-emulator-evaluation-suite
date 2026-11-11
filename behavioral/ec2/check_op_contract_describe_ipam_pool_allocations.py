"""op-contract-describeIpamPoolAllocations."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeIpamPoolAllocations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """DescribeIpamPoolAllocations returns an allocation carved from a provisioned IPAM pool with its ID and
    CIDR, and DryRun answers DryRunOperation with its exact message."""
    ec2 = ctx.client("ec2")
    pool_id = _create_ready_ipam_pool(ctx, ec2)

    ec2.provision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr="10.91.0.0/16")
    _poll_until(
        lambda: ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id)["IpamPoolCidrs"],
        lambda cidrs: any(c["State"] == "provisioned" for c in cidrs),
        timeout_s=60.0,
        interval_s=3.0,
    )

    allocation = ec2.allocate_ipam_pool_cidr(IpamPoolId=pool_id, NetmaskLength=24)[
        "IpamPoolAllocation"
    ]
    alloc_id = allocation["IpamPoolAllocationId"]
    ctx.on_cleanup(
        lambda: ec2.release_ipam_pool_allocation(
            IpamPoolId=pool_id,
            IpamPoolAllocationId=alloc_id,
            Cidr=allocation["Cidr"],
        )
    )

    def probe():
        # Right after AllocateIpamPoolCidr this read can raise InvalidIpamPoolAllocationId.NotFound until
        # the allocation propagates; keep polling.
        try:
            resp = ec2.describe_ipam_pool_allocations(IpamPoolAllocationIds=[alloc_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidIpamPoolAllocationId.NotFound":
                return []
            raise
        return resp.get("IpamPoolAllocations", [])

    items = _poll_until(probe, lambda v: len(v) == 1, timeout_s=30.0, interval_s=2.0)
    described = items[0]
    assert described["IpamPoolAllocationId"] == alloc_id, (
        f"expected allocation id {alloc_id}, got {described['IpamPoolAllocationId']}"
    )
    assert described["Cidr"] == allocation["Cidr"], (
        f"expected cidr {allocation['Cidr']}, got {described['Cidr']}"
    )

    code, message = _error(lambda: ec2.describe_ipam_pool_allocations(DryRun=True))
    assert code == "DryRunOperation", f"unexpected error code: {code}"
    assert message == (
        "Request would have succeeded, but DryRun flag is set."
    ), f"unexpected DryRunOperation message: {message!r}"


def _create_ready_ipam_pool(ctx, ec2) -> str:
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = ec2.create_ipam(
        Description=name,
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    # Cascade deletes the scope, the pool and the pool's provisioned CIDR with the
    # IPAM; deleting the pool on its own fails while a CIDR is still provisioned.
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    scope = ec2.create_ipam_scope(IpamId=ipam_id)["IpamScope"]
    scope_id = scope["IpamScopeId"]

    pool = ec2.create_ipam_pool(IpamScopeId=scope_id, AddressFamily="ipv4")["IpamPool"]
    pool_id = pool["IpamPoolId"]

    _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]["State"],
        lambda state: state == "create-complete",
        timeout_s=60.0,
        interval_s=3.0,
    )
    return pool_id


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn() and return the (code, message) of the error it raises. A call
    that SUCCEEDS raises AssertionError: real AWS refuses it, so acceptance must
    not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
