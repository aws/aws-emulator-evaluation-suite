"""subnet-cidr-outside-vpc-range-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "subnet-cidr-outside-vpc-range-fails"
GROUP = 'error-semantics'
SERVICES = ['ec2']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSubnet with a CIDR outside the parent VPC's CIDR range must fail with InvalidSubnet.Range."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.3.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"] == "available":
            break
        time.sleep(2)

    control_subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.3.1.0/24",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=control_subnet_id))
    control = ec2.describe_subnets(SubnetIds=[control_subnet_id])["Subnets"][0]
    assert control["CidrBlock"] == "10.3.1.0/24", f"positive control: expected in-range CIDR to be accepted, got {control['CidrBlock']}"

    try:
        ec2.create_subnet(VpcId=vpc_id, CidrBlock="192.168.0.0/24")
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidSubnet.Range", f"expected InvalidSubnet.Range, got {code}"
    assert message == "The CIDR '192.168.0.0/24' is invalid.", f"unexpected message: {message!r}"

    subnet_ids_in_vpc = {
        s["SubnetId"]
        for s in ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Subnets"]
    }
    assert subnet_ids_in_vpc == {control_subnet_id}, (
        f"expected only the positive-control subnet {control_subnet_id} in {vpc_id}, "
        f"got {sorted(subnet_ids_in_vpc)} (out-of-range CreateSubnet must have no effect)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
