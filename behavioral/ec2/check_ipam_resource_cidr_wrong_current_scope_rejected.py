"""ipam-resource-cidr-wrong-current-scope-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ipam-resource-cidr-wrong-current-scope-rejected"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ec2-ipam")
def run(ctx) -> None:
    """ModifyIpamResourceCidr rejects a CurrentIpamScopeId that does not match the resource's scope and
    leaves its monitoring state untouched, while the same call with the correct scope ID succeeds
    (positive control)."""
    ec2 = ctx.client("ec2")

    ipam_name = ctx.unique_name("sim2real-ipam-")
    ipam = ec2.create_ipam(
        Description=ipam_name,
        OperatingRegions=[{"RegionName": ctx.region}],
    )["Ipam"]
    ipam_id = ipam["IpamId"]
    ctx.on_cleanup(lambda: ec2.delete_ipam(IpamId=ipam_id, Cascade=True))
    ec2.create_tags(Resources=[ipam_id], Tags=[{"Key": "Name", "Value": ipam_name}])
    ipam = _poll_until(
        lambda: ec2.describe_ipams(IpamIds=[ipam_id])["Ipams"][0],
        lambda i: i["State"] == "create-complete",
        timeout_s=60,
    )
    private_scope_id = ipam["PrivateDefaultScopeId"]
    public_scope_id = ipam["PublicDefaultScopeId"]

    cidr = "10.203.0.0/16"
    vpc_name = ctx.unique_name("sim2real-vpc-")
    vpc_id = ec2.create_vpc(CidrBlock=cidr)["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": vpc_name}])

    def _find_resource_cidr():
        entries = ec2.get_ipam_resource_cidrs(
            IpamScopeId=private_scope_id, ResourceId=vpc_id
        )["IpamResourceCidrs"]
        return entries[0] if entries else None

    # IPAM resource discovery is a background scan with no documented promptness SLA;
    # measured on real AWS (us-west-2) a fresh VPC in a fresh IPAM's private scope has been
    # observed still undiscovered after 480s, so this window carries headroom above that
    # rather than a guess.
    resource_cidr = None
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        resource_cidr = _find_resource_cidr()
        if resource_cidr is not None:
            break
        time.sleep(2)
    if resource_cidr is None:
        raise AssertionError(
            f"IPAM did not discover VPC {vpc_id} in the private scope within 900s; "
            "discovery scan latency is undocumented and can exceed this window"
        )

    # Baseline is the target's own reported state, not a guessed literal: a resource that
    # was merely discovered (never allocated from an IPAM pool) need not read "managed", and
    # asserting a specific guessed value here is not grounded. What matters is that the baseline is not already
    # "ignored", so the transition this check exists to prove is actually observable.
    baseline_state = resource_cidr["ManagementState"]
    assert baseline_state != "ignored", (
        f"resource CIDR for {vpc_id} arrived with ManagementState={baseline_state!r} before "
        "Monitored=False was ever called; the transition this check exists to prove cannot be "
        "observed from an already-ignored baseline"
    )

    try:
        result = ec2.modify_ipam_resource_cidr(
            ResourceId=vpc_id,
            ResourceCidr=cidr,
            ResourceRegion=ctx.region,
            CurrentIpamScopeId=public_scope_id,  # wrong: VPC actually lives in the private scope
            Monitored=False,
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        raise AssertionError(
            f"expected the wrong CurrentIpamScopeId to be rejected, but the call SUCCEEDED: {result!r}"
        )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == f"The scope {public_scope_id} is not private.", (
        f"unexpected InvalidParameterValue message {message!r}"
    )

    # Effect absent: the resource's management state was not changed by the rejected call.
    unchanged = _find_resource_cidr()
    assert unchanged is not None, f"resource CIDR for {vpc_id} disappeared after the rejected call"
    assert unchanged["ManagementState"] == baseline_state, (
        f"ManagementState moved from {baseline_state!r} to {unchanged['ManagementState']!r} "
        "after a call that should have been rejected with no effect"
    )

    # Positive control: the identical call with the correct scope succeeds. The resulting
    # ManagementState=="ignored" is populated by the same background scan as discovery above,
    # not by the mutating call's own response, so it is on that scan's cadence rather than an
    # API-response latency -- an unpolled single read here would flake against a correct target.
    ec2.modify_ipam_resource_cidr(
        ResourceId=vpc_id,
        ResourceCidr=cidr,
        ResourceRegion=ctx.region,
        CurrentIpamScopeId=private_scope_id,
        Monitored=False,
    )
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline:
        changed = _find_resource_cidr()
        if changed is not None and changed["ManagementState"] == "ignored":
            break
        time.sleep(2)
    else:
        raise AssertionError(
            f"ManagementState for {vpc_id} never transitioned to 'ignored' within 600s after "
            f"the corrected call succeeded (baseline was {baseline_state!r})"
        )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
