"""op-contract-get-ipam-pool-allocations."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-get-ipam-pool-allocations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """GetIpamPoolAllocations lists exactly one entry, with its CIDR, for a new allocation (also when
    filtered by its id); an unknown pool id fails with a NotFound or Malformed code naming IpamPool."""
    ec2 = ctx.client("ec2")

    ipam_name = ctx.unique_name("sim2real-ipam-")
    ipam = ec2.create_ipam(
        Description=ipam_name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[
            {"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": ipam_name}]}
        ],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    private_scope_id = ipam["PrivateDefaultScopeId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))

    pool_name = ctx.unique_name("sim2real-pool-")
    pool = ec2.create_ipam_pool(
        IpamScopeId=private_scope_id,
        AddressFamily="ipv4",
        Locale=ctx.region,
        Description=pool_name,
        TagSpecifications=[
            {"ResourceType": "ipam-pool", "Tags": [{"Key": "Name", "Value": pool_name}]}
        ],
    )["IpamPool"]
    pool_id = pool["IpamPoolId"]
    _wait_pool_state(ec2, pool_id, {"create-complete"})

    cidr = "10.201.0.0/16"
    ec2.provision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=cidr)
    _wait_pool_cidr_state(ec2, pool_id, cidr, {"provisioned"})

    alloc_cidr = "10.201.0.0/24"
    allocation = ec2.allocate_ipam_pool_cidr(
        IpamPoolId=pool_id, Cidr=alloc_cidr, Description="sim2real-alloc"
    )["IpamPoolAllocation"]
    alloc_id = allocation["IpamPoolAllocationId"]

    # success-path contract: the allocation we just made is listed, with the right CIDR.
    # Listing is eventually consistent with the allocate call, so poll with a bound
    # rather than asserting immediately.
    matches = _poll_until(
        lambda: [
            a
            for a in ec2.get_ipam_pool_allocations(IpamPoolId=pool_id)["IpamPoolAllocations"]
            if a["IpamPoolAllocationId"] == alloc_id
        ],
        lambda ms: len(ms) == 1,
        timeout_s=120.0,
        interval_s=3.0,
    )
    assert matches is not None and len(matches) == 1, (
        f"expected exactly one match for {alloc_id} to appear within the poll window"
    )
    assert matches[0]["Cidr"] == alloc_cidr

    # scoping by IpamPoolAllocationId narrows the result set to exactly one entry.
    scoped = ec2.get_ipam_pool_allocations(
        IpamPoolId=pool_id, IpamPoolAllocationId=alloc_id
    )["IpamPoolAllocations"]
    assert len(scoped) == 1 and scoped[0]["Cidr"] == alloc_cidr

    # error boundary: a well-formed but nonexistent pool id is rejected distinctly.
    code = _error_code(
        lambda: ec2.get_ipam_pool_allocations(IpamPoolId="ipam-pool-00000000000000000")
    )
    _assert_invalid_id(code, "IpamPool")


def _wait_pool_state(ec2, pool_id, target_states, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        pools = ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"]
        if pools:
            state = pools[0]["State"]
            if state in target_states:
                return state
            if state == "create-failed":
                raise AssertionError(f"pool {pool_id} entered create-failed")
        time.sleep(interval_s)
    raise AssertionError(f"pool {pool_id} never reached {target_states}, last state {state}")


def _wait_pool_cidr_state(ec2, pool_id, cidr, target_states, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    state = None
    while time.monotonic() < deadline:
        cidrs = ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id)["IpamPoolCidrs"]
        for entry in cidrs:
            if entry["Cidr"] == cidr:
                state = entry["State"]
                if state in target_states:
                    return state
                if state == "failed-provision":
                    raise AssertionError(f"cidr {cidr} failed to provision")
        time.sleep(interval_s)
    raise AssertionError(f"cidr {cidr} never reached {target_states}, last state {state}")


def _poll_until(fn, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = fn()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _assert_invalid_id(code, token):
    assert code is not None, "expected a ClientError but the call succeeded"
    assert code.endswith(".NotFound") or code.endswith(".Malformed"), (
        f"expected a *.NotFound/*.Malformed error code, got {code!r}"
    )
    assert token.lower() in code.lower(), f"expected {token!r} referenced in code, got {code!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
