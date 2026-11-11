"""op-contract-describeSecurityGroupReferences."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeSecurityGroupReferences"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeSecurityGroupReferences reports which VPCs (via peering/TGW) reference a
    security group -- for a fresh, unpeered group that is an empty set -- and rejects a
    security group ID that does not exist in this account."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.71.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-sgref-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _wait_for_vpc_available(ec2, vpc_id)

    group_name = ctx.unique_name("sim2real-behav-sgref-")
    group_id = ec2.create_security_group(
        GroupName=group_name,
        Description="sim2real behavioral check: security group references",
        VpcId=vpc_id,
        TagSpecifications=[
            {
                "ResourceType": "security-group",
                "Tags": [{"Key": "Name", "Value": group_name}],
            }
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: ec2.delete_security_group(GroupId=group_id))

    resp = ec2.describe_security_group_references(GroupId=[group_id])
    key, refs = _sole_list_field(resp)
    assert isinstance(refs, list), f"{key} is not a list: {refs!r}"
    assert refs == [], f"a freshly created, unpeered security group should have no references, got {refs!r}"

    # A synthetically-constructed ID (e.g. flipping a hex digit of a real one) is not a
    # reliable way to get a "well-formed but nonexistent" ID: AWS's long-ID format validation
    # can reject numeric values outside the currently-issued range as InvalidGroupId.Malformed
    # rather than NotFound, regardless of how the digits were perturbed. Instead, create a
    # throwaway security group, delete it, and reuse its ID -- this is guaranteed to be
    # well-formed (AWS issued it) and guaranteed to no longer exist.
    fake_group_id = _create_and_delete_group(ctx, ec2, vpc_id)
    code, message = _poll_until_rejected(
        lambda: ec2.describe_security_group_references(GroupId=[fake_group_id]),
        timeout_s=60,
        interval_s=5,
    )
    assert code == "InvalidGroup.NotFound", f"expected InvalidGroup.NotFound, got {code!r}"
    expected_message = f"The security group '{fake_group_id}' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _sole_list_field(resp):
    skip = {"ResponseMetadata", "NextToken", "RequestId"}
    for k, v in resp.items():
        if k in skip:
            continue
        if isinstance(v, list):
            return k, v
    raise AssertionError(f"no list field found in response: {sorted(resp.keys())}")


def _create_and_delete_group(ctx, ec2, vpc_id):
    name = ctx.unique_name("sim2real-behav-sgref-gone-")
    gid = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral check: throwaway group for NotFound assertion",
        VpcId=vpc_id,
    )["GroupId"]
    ec2.delete_security_group(GroupId=gid)
    return gid


def _poll_until_rejected(fn, *, timeout_s=60.0, interval_s=5.0):
    """Call fn() until it is rejected and return the rejection's (code, message). A deleted
    group can stay describable for a few seconds, so a success is retried until timeout_s, then
    raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"expected the call to be rejected within {timeout_s}s, but it kept SUCCEEDING; last {result!r}"
            )
        time.sleep(interval_s)


def _wait_for_vpc_available(ec2, vpc_id, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        last_state = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"]
        if last_state == "available":
            return
        time.sleep(interval_s)
    raise AssertionError(f"VPC {vpc_id} did not become available within {timeout_s}s, last state {last_state!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
