"""modify-ipam-resource-cidr-updates-monitoring-state."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "modify-ipam-resource-cidr-updates-monitoring-state"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """After ModifyIpamResourceCidr(Monitored=False) on a discovered VPC whose ManagementState is
    not yet ignored, GetIpamResourceCidrs reports it ignored within a bounded poll on IPAM's scan.
    """
    ec2 = ctx.client("ec2")
    ipam_name = ctx.unique_name("sim2real-behav-ipam-")
    ipam = _create_ipam_retrying_slot(
        ctx,
        ec2,
        Description=ipam_name,
        OperatingRegions=[{"RegionName": ctx.region}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    scope_id = ipam["PrivateDefaultScopeId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))
    ec2.create_tags(Resources=[ipam_id], Tags=[{"Key": "Name", "Value": ipam_name}])
    _wait_ipam_state(ec2, ipam_id, "create-complete")

    vpc_cidr = "10.220.0.0/16"
    vpc_name = ctx.unique_name("sim2real-behav-vpc-")
    # Tagged at create: EC2 is eventually consistent, so a CreateTags right after CreateVpc can
    # answer InvalidVpcID.NotFound.
    vpc_id = ec2.create_vpc(
        CidrBlock=vpc_cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    # IPAM resource discovery is a background scan with no documented promptness SLA; a fresh
    # VPC can stay undiscovered for several minutes, so the window carries headroom.
    resource = _poll_for_resource_cidr(ec2, scope_id, vpc_id, timeout_s=900.0)
    assert resource is not None, "IPAM never surfaced the VPC's resource CIDR in the private scope"

    # A baseline read proves the eventual ManagementState=ignored is caused by Monitored=False,
    # not a static value every resource already carries (which no post-only read could rule out).
    baseline_state = resource["ManagementState"]
    assert baseline_state != "ignored", (
        f"resource CIDR arrived with ManagementState={baseline_state!r} before Monitored=False was "
        "ever called; the transition this check exists to prove cannot be observed from an "
        "already-ignored baseline"
    )

    ec2.modify_ipam_resource_cidr(
        ResourceId=vpc_id,
        ResourceCidr=resource["ResourceCidr"],
        ResourceRegion=resource["ResourceRegion"],
        CurrentIpamScopeId=scope_id,
        Monitored=False,
    )

    # ManagementState is populated by the same background scan as initial discovery above, not by
    # the mutating call itself, so it is on that scan's cadence rather than an API-response latency.
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        updated = _find_resource_cidr(ec2, scope_id, vpc_id)
        if updated is not None and updated["ManagementState"] == "ignored":
            return
        time.sleep(2)
    raise AssertionError(
        f"VPC resource CIDR never transitioned to ManagementState=ignored after Monitored=False "
        f"(baseline was {baseline_state!r})"
    )


def _wait_ipam_state(ec2, ipam_id, state, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ipam = ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0]
        if ipam["State"] == state:
            return
        time.sleep(3)
    raise AssertionError(f"IPAM never reached state {state!r}")


def _find_resource_cidr(ec2, scope_id, vpc_id):
    resp = ec2.get_ipam_resource_cidrs(IpamScopeId=scope_id, ResourceId=vpc_id)
    for r in resp.get("IpamResourceCidrs", []):
        if r.get("ResourceId") == vpc_id:
            return r
    return None


def _poll_for_resource_cidr(ec2, scope_id, vpc_id, timeout_s):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        found = _find_resource_cidr(ec2, scope_id, vpc_id)
        if found is not None:
            return found
        time.sleep(2)
    return None


def _create_ipam_retrying_slot(ctx, ec2, **kwargs) -> dict:
    """CreateIpam, retrying ONLY the per-Region quota refusal (IPAMs per Region is 1 by default)
    while another IPAM finishes deleting, every 2 s to a deadline capped by ctx.time_left()."""
    from botocore.exceptions import ClientError

    left = ctx.time_left()
    cap = 480.0 if left is None else min(480.0, left)
    deadline = time.monotonic() + cap
    while True:
        try:
            return ec2.create_ipam(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceLimitExceeded":
                raise
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"no IPAM slot freed within {cap:.0f} s: "
                    f"{exc.response['Error'].get('Message')!r}"
                ) from exc
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
