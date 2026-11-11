"""op-contract-modify-ipam-pool."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-ipam-pool"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ModifyIpamPool sets description, netmask min 16 / max 24 / default 20 and AutoImport, echoed and
    read back; a min above the max fails with InvalidParameterValue and its exact message and leaves
    the bounds unchanged."""
    ec2 = ctx.client("ec2")
    _ipam_id, private_scope_id, _public_scope_id = _create_ipam(ctx, ec2)
    pool_id = _create_ipam_pool(ctx, ec2, private_scope_id)

    resp = ec2.modify_ipam_pool(
        IpamPoolId=pool_id,
        Description="updated-by-sim2real",
        AllocationMinNetmaskLength=16,
        AllocationMaxNetmaskLength=24,
        AllocationDefaultNetmaskLength=20,
        AutoImport=True,
    )
    pool = resp["IpamPool"]
    assert pool["Description"] == "updated-by-sim2real", f"expected updated description, got {pool['Description']!r}"
    assert pool["AllocationMinNetmaskLength"] == 16, f"expected min netmask 16, got {pool['AllocationMinNetmaskLength']!r}"
    assert pool["AllocationMaxNetmaskLength"] == 24, f"expected max netmask 24, got {pool['AllocationMaxNetmaskLength']!r}"
    assert pool["AllocationDefaultNetmaskLength"] == 20, f"expected default netmask 20, got {pool['AllocationDefaultNetmaskLength']!r}"
    assert pool["AutoImport"] is True, f"expected AutoImport True, got {pool['AutoImport']!r}"

    # independent read at the destination: the mutating call's own response is not enough
    described = ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]
    assert described["Description"] == "updated-by-sim2real", (
        f"expected persisted description updated-by-sim2real, got {described['Description']!r}"
    )
    assert described["AllocationMinNetmaskLength"] == 16, (
        f"expected persisted min netmask 16, got {described['AllocationMinNetmaskLength']!r}"
    )
    assert described["AllocationMaxNetmaskLength"] == 24, (
        f"expected persisted max netmask 24, got {described['AllocationMaxNetmaskLength']!r}"
    )
    assert described["AllocationDefaultNetmaskLength"] == 20, (
        f"expected persisted default netmask 20, got {described['AllocationDefaultNetmaskLength']!r}"
    )
    assert described["AutoImport"] is True, f"expected persisted AutoImport True, got {described['AutoImport']!r}"

    # error boundary: minimum netmask length must be less than the maximum (always-invalid input,
    # no restore beat by construction)
    code, message = _error(
        lambda: ec2.modify_ipam_pool(
            IpamPoolId=pool_id, AllocationMinNetmaskLength=28, AllocationMaxNetmaskLength=24
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code}"
    assert message == "The default netmask length cannot be smaller than the min.", message

    # effect absent: the rejected call must not have perturbed the pool's prior valid state
    reread = ec2.describe_ipam_pools(IpamPoolIds=[pool_id])["IpamPools"][0]
    assert reread["AllocationMinNetmaskLength"] == 16, (
        f"rejected modify must not change min netmask; expected 16, got {reread['AllocationMinNetmaskLength']!r}"
    )
    assert reread["AllocationMaxNetmaskLength"] == 24, (
        f"rejected modify must not change max netmask; expected 24, got {reread['AllocationMaxNetmaskLength']!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    from botocore.exceptions import ClientError

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
    name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = ec2.create_ipam(
        Description=name,
        OperatingRegions=[{"RegionName": ctx.region}],
        TagSpecifications=[{"ResourceType": "ipam", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]

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


def _create_ipam_pool(ctx, ec2, scope_id):
    name = ctx.unique_name("sim2real-behav-pool-")
    pool = ec2.create_ipam_pool(
        IpamScopeId=scope_id,
        AddressFamily="ipv4",
        Locale=ctx.region,
        Description=name,
        TagSpecifications=[{"ResourceType": "ipam-pool", "Tags": [{"Key": "Name", "Value": name}]}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
