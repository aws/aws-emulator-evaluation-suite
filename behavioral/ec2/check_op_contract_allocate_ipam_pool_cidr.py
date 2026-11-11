"""op-contract-allocateIpamPoolCidr."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-allocateIpamPoolCidr"
GROUP = "error-semantics"
SERVICES = ["ec2"]
DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control", "resource:account-singleton:ec2-ipam",
)
def run(ctx) -> None:
    """AllocateIpamPoolCidr carves a CIDR from a provisioned IPAM pool that an independent read
    shows, then with DryRun fails DryRunOperation and on a well-formed nonexistent pool id
    fails InvalidIpamPoolId.NotFound, each with its exact message.
    """
    ec2 = ctx.client("ec2")
    pool_id = _create_ready_ipam_pool(ctx, ec2)

    parent_cidr = "10.77.0.0/24"
    ec2.provision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=parent_cidr)
    _poll_until(
        lambda: ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id)["IpamPoolCidrs"],
        lambda cidrs: any(
            c["Cidr"] == parent_cidr and c["State"] == "provisioned" for c in cidrs
        ),
        timeout_s=60.0,
        interval_s=3.0,
        description="parent CIDR reaching 'provisioned'",
    )

    allocation = ec2.allocate_ipam_pool_cidr(IpamPoolId=pool_id, NetmaskLength=28)[
        "IpamPoolAllocation"
    ]
    alloc_id = allocation["IpamPoolAllocationId"]
    alloc_cidr = allocation["Cidr"]
    ctx.on_cleanup(
        lambda: ec2.release_ipam_pool_allocation(
            IpamPoolId=pool_id, IpamPoolAllocationId=alloc_id, Cidr=alloc_cidr
        )
    )

    def _find_allocation():
        try:
            allocs = ec2.describe_ipam_pool_allocations(
                IpamPoolAllocationIds=[alloc_id]
            )["IpamPoolAllocations"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidIpamPoolAllocationId.NotFound":
                return None
            raise
        return allocs[0] if allocs else None

    seen = _poll_until(
        _find_allocation,
        lambda v: v is not None,
        timeout_s=30.0,
        interval_s=2.0,
        description="allocation visible via DescribeIpamPoolAllocations",
    )
    assert seen["Cidr"] == alloc_cidr, f"expected {alloc_cidr!r}, got {seen['Cidr']!r}"

    fake_pool_id = "ipam-pool-0123456789abcdef0"

    info = _client_error(
        lambda: ec2.allocate_ipam_pool_cidr(
            IpamPoolId=fake_pool_id, NetmaskLength=28, DryRun=True
        )
    )
    assert info["code"] == "DryRunOperation", f"expected DryRunOperation, got {info['code']!r}"
    assert info["message"] == DRY_RUN_MESSAGE, (
        f"expected message {DRY_RUN_MESSAGE!r}, got {info['message']!r}"
    )

    info2 = _client_error(
        lambda: ec2.allocate_ipam_pool_cidr(IpamPoolId=fake_pool_id, NetmaskLength=28)
    )
    assert info2["code"] == "InvalidIpamPoolId.NotFound", (
        f"unexpected code {info2['code']!r}"
    )
    expected2 = f"The ipam-pool ID '{fake_pool_id}' does not exist"
    assert info2["message"] == expected2, (
        f"expected message {expected2!r}, got {info2['message']!r}"
    )


def _create_ready_ipam_pool(ctx, ec2) -> str:
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = ec2.create_ipam(
        Description=name,
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))
    scope_id = ipam["PrivateDefaultScopeId"]

    pool = ec2.create_ipam_pool(IpamScopeId=scope_id, AddressFamily="ipv4")["IpamPool"]
    pool_id = pool["IpamPoolId"]

    _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]["State"],
        lambda state: state == "create-complete",
        timeout_s=60.0,
        interval_s=3.0,
        description="IPAM pool reaching 'create-complete'",
    )
    return pool_id


def _poll_until(probe, predicate, *, timeout_s, interval_s, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return {"code": err["Code"], "message": err.get("Message")}
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
