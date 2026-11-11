"""op-contract-modify-ipam-resource-cidr."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-modify-ipam-resource-cidr"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ModifyIpamResourceCidr toggles monitoring for a discovered resource CIDR: a VPC outside every
    IPAM pool goes unmanaged -> ignored -> unmanaged, on IPAM's background-scan cadence."""
    ec2 = ctx.client("ec2")
    _ipam_id, private_scope_id, _public_scope_id = _create_ipam(ctx, ec2)

    try:
        vpc = ec2.create_vpc(CidrBlock="10.77.0.0/24")["Vpc"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "VpcLimitExceeded":
            raise AssertionError("account/region is at its VPC quota; cannot create a discoverable test resource")
        raise
    vpc_id = vpc["VpcId"]
    vpc_cidr = vpc["CidrBlock"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}])

    # IPAM resource discovery backfills existing resources asynchronously, with no documented SLA; a fresh
    # VPC in a fresh IPAM's private scope has been observed undiscovered after 480s, so wait 900s.
    discovered = _poll_until(
        lambda: next(
            (
                c
                for c in ec2.get_ipam_resource_cidrs(IpamScopeId=private_scope_id, ResourceId=vpc_id)[
                    "IpamResourceCidrs"
                ]
                if c["ResourceCidr"] == vpc_cidr
            ),
            None,
        ),
        lambda c: c is not None,
        timeout_s=900,
        interval_s=15,
    )
    if discovered is None:
        raise AssertionError(
            "IPAM resource discovery did not observe the test VPC's CIDR within the poll window"
        )
    assert discovered["ManagementState"] == "unmanaged", (
        f"expected a VPC outside every IPAM pool to be discovered unmanaged, got {discovered['ManagementState']!r}"
    )

    def _current_management_state():
        entries = ec2.get_ipam_resource_cidrs(IpamScopeId=private_scope_id, ResourceId=vpc_id)[
            "IpamResourceCidrs"
        ]
        match = next((c for c in entries if c["ResourceCidr"] == vpc_cidr), None)
        assert match is not None, f"resource CIDR {vpc_cidr} vanished from GetIpamResourceCidrs"
        return match["ManagementState"]

    # success path: flip monitoring off, then back on -- each confirmed by an
    # independent GetIpamResourceCidrs read, not by the mutating call's own response.
    ec2.modify_ipam_resource_cidr(
        ResourceId=vpc_id,
        ResourceCidr=vpc_cidr,
        ResourceRegion=ctx.region,
        CurrentIpamScopeId=private_scope_id,
        Monitored=False,
    )
    state = _poll_until(
        _current_management_state, lambda s: s == "ignored", timeout_s=600, interval_s=15,
        description="GetIpamResourceCidrs reflecting Monitored=False as ManagementState=ignored",
    )
    assert state == "ignored", f"expected ManagementState=ignored after Monitored=False, got {state!r}"

    ec2.modify_ipam_resource_cidr(
        ResourceId=vpc_id,
        ResourceCidr=vpc_cidr,
        ResourceRegion=ctx.region,
        CurrentIpamScopeId=private_scope_id,
        Monitored=True,
    )
    state = _poll_until(
        _current_management_state, lambda s: s == "unmanaged", timeout_s=600, interval_s=15,
        description="GetIpamResourceCidrs reflecting Monitored=True as ManagementState=unmanaged",
    )
    assert state == "unmanaged", f"expected ManagementState=unmanaged after Monitored=True, got {state!r}"

    # error boundary: a resource id IPAM has never discovered in this scope
    code, message = _error(
        lambda: ec2.modify_ipam_resource_cidr(
            ResourceId="vpc-00000000000000000",
            ResourceCidr="10.250.0.0/24",
            ResourceRegion=ctx.region,
            CurrentIpamScopeId=private_scope_id,
            Monitored=False,
        )
    )
    assert code == "InvalidResourceCidr.NotFound", f"expected InvalidResourceCidr.NotFound, got {code}"
    assert message == (
        "The specified resource ID vpc-00000000000000000 and CIDR 10.250.0.0/24 does not exist."
    ), message


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


def _create_ipam(ctx, ec2):
    ipam = ec2.create_ipam(
        Description=ctx.unique_name("sim2real-behav-ipam-"),
        OperatingRegions=[{"RegionName": ctx.region}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
