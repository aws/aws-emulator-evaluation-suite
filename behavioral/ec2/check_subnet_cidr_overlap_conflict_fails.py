"""subnet-cidr-overlap-conflict-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subnet-cidr-overlap-conflict-fails"
GROUP = 'overly-permissive'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A subnet whose CIDR overlaps an existing one in the VPC fails with InvalidSubnet.Conflict
    and leaves no subnet behind; once the conflicting subnet is removed the identical call succeeds.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.4.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    _poll_until(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
        timeout_s=60, interval_s=2,
    )

    # Positive control: a subnet create in this VPC succeeds.
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.4.1.0/24", TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Subnet"]["SubnetId"]
    cleanup_ids = [subnet_id]
    ctx.on_cleanup(lambda: _delete_remaining(ec2, cleanup_ids))

    conflict_cidr = "10.4.1.128/25"

    # Break exactly one thing: request a CIDR that falls inside the existing subnet's range.
    code, message = _error(lambda: ec2.create_subnet(VpcId=vpc_id, CidrBlock=conflict_cidr))
    assert code == "InvalidSubnet.Conflict", f"expected InvalidSubnet.Conflict, got {code!r}"
    expected_message = f"The CIDR '{conflict_cidr}' conflicts with another subnet"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: an independent read shows the rejected create left no phantom subnet.
    after_reject = [
        s["SubnetId"]
        for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    ]
    assert after_reject == [subnet_id], f"expected only {subnet_id!r} present, got {after_reject!r}"

    # Restore: remove the conflicting subnet, then the identical call must succeed.
    ec2.delete_subnet(SubnetId=subnet_id)
    _poll_until(
        lambda: _subnet_lookup_code(ec2, subnet_id),
        lambda c: c == "InvalidSubnetID.NotFound",
        timeout_s=60, interval_s=2,
    )

    new_subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=conflict_cidr)["Subnet"]["SubnetId"]
    cleanup_ids.append(new_subnet_id)

    # Terminal read: an independent DescribeSubnets confirms the identical call now succeeded.
    restored = ec2.describe_subnets(SubnetIds=[new_subnet_id])["Subnets"]
    assert len(restored) == 1, f"expected the restored subnet to be readable, got {restored!r}"
    assert restored[0]["CidrBlock"] == conflict_cidr, (
        f"expected CidrBlock {conflict_cidr!r}, got {restored[0]['CidrBlock']!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _subnet_lookup_code(ec2, subnet_id):
    """DescribeSubnets' error code for subnet_id, or "present" while it is still listed."""
    try:
        ec2.describe_subnets(SubnetIds=[subnet_id])
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return "present"


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


def _delete_remaining(ec2, subnet_ids):
    for sid in subnet_ids:
        try:
            ec2.delete_subnet(SubnetId=sid)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSubnetID.NotFound":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
