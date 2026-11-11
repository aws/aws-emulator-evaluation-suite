"""op-contract-release-ipam-pool-allocation."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-release-ipam-pool-allocation"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ReleaseIpamPoolAllocation with DryRun fails with DryRunOperation; without DryRun it returns Success
    true and the allocation leaves GetIpamPoolAllocations; a second release fails with
    InvalidParameterCombination and its exact message."""
    ec2 = ctx.client("ec2")

    # IPAMs are an extremely low, account-wide quota (this account is limited to a single IPAM),
    # and that single IPAM tends to persist indefinitely once it exists -- unlike a per-check TGW
    # or VPC, there's no reason to expect a slot to ever free up, so retrying CreateIpam across
    # ResourceLimitExceeded is fundamentally unlike retrying transient contention: if an IPAM
    # already exists (ours or anyone else's), CreateIpam can never succeed again. We don't need to
    # OWN the IPAM though -- we only need a scope to create our own pool in, and we clean up
    # everything we add (pool, provisioned CIDR, allocation) -- so reuse any existing,
    # fully-created IPAM when one is present, and only create (and later delete) our own when none
    # exists yet.
    #
    # A prior run of this same check that failed mid-test (e.g. before its cleanup ran) can leave
    # an IPAM allocated, which then causes CreateIpam here to hit ResourceLimitExceeded. Reclaim
    # any such leaked IPAM (tagged by this check) before creating a new one.
    _release_stale_ipams(ec2)

    reused_ipam = _reusable_ipam(ec2)
    if reused_ipam is not None:
        ipam_id = reused_ipam["IpamId"]
        scope_id = reused_ipam["PrivateDefaultScopeId"]
    else:
        # Even after reclaiming this check's own leaked IPAMs, CreateIpam can still transiently hit
        # ResourceLimitExceeded while another check's promptly cleaned-up IPAM still occupies the
        # account's single-IPAM quota slot; retry
        # until it frees up instead of failing outright on what is contention, not a real capacity
        # shortfall.
        ipam_id = _create_ipam_with_retry(
            ec2,
            description=ctx.unique_name("sim2real-ipam-"),
            region=ctx.region,
            timeout_s=650,
            interval_s=20,
        )
        ctx.on_cleanup(lambda: _delete_ipam(ec2, ipam_id))

        # CreateIpam's own response can precede full initialization -- PrivateDefaultScopeId is
        # populated once the IPAM reaches create-complete, so poll DescribeIpams rather than assuming
        # it is already present in the create response.
        ipam = _poll_until(
            lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
            lambda i: i["State"] == "create-complete",
            timeout_s=60,
            interval_s=3,
        )
        scope_id = ipam["PrivateDefaultScopeId"]

    # The pool/allocation CIDRs below may live inside a reused IPAM that other checks also use, so
    # pick a pseudo-unique range instead
    # of a fixed constant to keep collisions with a concurrently-running instance of this same check
    # unlikely.
    octet = random.randint(16, 250)
    pool_cidr = f"10.{octet}.0.0/16"

    pool_id = ec2.create_ipam_pool(
        IpamScopeId=scope_id, AddressFamily="ipv4", Locale=ctx.region
    )["IpamPool"]["IpamPoolId"]
    ctx.on_cleanup(lambda: _delete_pool(ec2, pool_id))
    _poll_until(
        lambda: ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]["State"],
        lambda s: s == "create-complete",
        timeout_s=60,
        interval_s=3,
    )

    ec2.provision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=pool_cidr)
    ctx.on_cleanup(lambda: _deprovision_pool_cidr(ec2, pool_id, pool_cidr))
    _poll_until(
        lambda: _pool_cidr_state(ec2, pool_id, pool_cidr),
        lambda s: s == "provisioned",
        timeout_s=60,
        interval_s=3,
    )

    alloc = ec2.allocate_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=f"10.{octet}.1.0/24")["IpamPoolAllocation"]
    allocation_id = alloc["IpamPoolAllocationId"]
    allocation_cidr = alloc["Cidr"]
    released = False

    def _cleanup_alloc():
        if not released:
            try:
                ec2.release_ipam_pool_allocation(
                    IpamPoolId=pool_id, IpamPoolAllocationId=allocation_id, Cidr=allocation_cidr
                )
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidIpamPoolId.NotFound":
                    raise

    ctx.on_cleanup(_cleanup_alloc)

    # allocate_ipam_pool_cidr can return before the allocation is visible via
    # GetIpamPoolAllocations due to eventual consistency; poll until it is.
    before = _poll_until(
        lambda: _get_allocation_or_none(ec2, pool_id, allocation_id),
        lambda a: a is not None,
        timeout_s=60,
        interval_s=3,
    )
    assert len(before) == 1 and before[0]["Cidr"] == allocation_cidr, (
        f"expected exactly 1 allocation with Cidr {allocation_cidr!r}, got {before!r}"
    )

    # --- error boundary: DryRun on the real allocation ---
    code, message = _error(
        lambda: ec2.release_ipam_pool_allocation(
            DryRun=True, IpamPoolId=pool_id, IpamPoolAllocationId=allocation_id, Cidr=allocation_cidr
        )
    )
    assert (code, message) == ("DryRunOperation", _DRY_RUN_MESSAGE), (
        f"expected DryRunOperation {_DRY_RUN_MESSAGE!r}, got {code!r} {message!r}"
    )

    # --- success path ---
    resp = ec2.release_ipam_pool_allocation(
        IpamPoolId=pool_id, IpamPoolAllocationId=allocation_id, Cidr=allocation_cidr
    )
    released = True
    assert resp["Success"] is True, f"expected Success=True, got {resp!r}"

    # GetIpamPoolAllocations for a released allocation id raises
    # InvalidIpamPoolAllocationId.NotFound rather than returning an empty list -- and the
    # disappearance can lag the release by a beat, symmetric to the appearance lag above.
    after = _poll_until(
        lambda: _get_allocation_or_none(ec2, pool_id, allocation_id),
        lambda a: a is None,
        timeout_s=30,
        interval_s=3,
    )
    assert after is None, f"allocation still present after release: {after}"

    # --- a second release of the same, now-gone allocation is not a repeatable success ---
    code2, message2 = _error(
        lambda: ec2.release_ipam_pool_allocation(
            IpamPoolId=pool_id, IpamPoolAllocationId=allocation_id, Cidr=allocation_cidr
        )
    )
    expected2 = f"No allocation found with ID {allocation_id} and CIDR {allocation_cidr}."
    assert (code2, message2) == ("InvalidParameterCombination", expected2), (
        f"expected InvalidParameterCombination {expected2!r} on double-release, got {code2!r} {message2!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _create_ipam_with_retry(ec2, *, description, region, timeout_s=650.0, interval_s=20.0):
    """See note above: retry CreateIpam across ResourceLimitExceeded (the account's single-IPAM
    quota under contention from this batch's concurrent checks) instead of failing outright on
    transient contention."""
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


def _reusable_ipam(ec2):
    """An existing, fully-created IPAM we can build our own pool on top of instead of creating a
    new one -- see the note at the call site on why reuse (not a longer retry) is the real fix for
    this quota."""
    paginator = ec2.get_paginator("describe_ipams")
    for page in paginator.paginate():
        for ipam in page["Ipams"]:
            if ipam["State"] == "create-complete":
                return ipam
    return None


def _get_allocation_or_none(ec2, pool_id, allocation_id):
    try:
        allocs = ec2.get_ipam_pool_allocations(IpamPoolId=pool_id, IpamPoolAllocationId=allocation_id)[
            "IpamPoolAllocations"
        ]
        return allocs if allocs else None
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidIpamPoolAllocationId.NotFound":
            return None
        raise


def _pool_cidr_state(ec2, pool_id, cidr):
    for c in ec2.get_ipam_pool_cidrs(IpamPoolId=pool_id)["IpamPoolCidrs"]:
        if c["Cidr"] == cidr:
            return c["State"]
    return "not-found"


def _deprovision_pool_cidr(ec2, pool_id, cidr):
    try:
        ec2.deprovision_ipam_pool_cidr(IpamPoolId=pool_id, Cidr=cidr)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidIpamPoolId.NotFound":
            raise


def _delete_pool(ec2, pool_id):
    try:
        ec2.delete_ipam_pool(IpamPoolId=pool_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidIpamPoolId.NotFound":
            raise


def _delete_ipam(ec2, ipam_id):
    try:
        ec2.delete_ipam(IpamId=ipam_id, Cascade=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidIpamId.NotFound":
            raise


def _release_stale_ipams(ec2):
    try:
        ipams = ec2.describe_ipams(Filters=[{"Name": "tag:sim2real-check", "Values": [CHECK]}])["Ipams"]
        for ipam in ipams:
            try:
                ec2.delete_ipam(IpamId=ipam["IpamId"], Cascade=True)
            except Exception:
                pass
    except Exception:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
