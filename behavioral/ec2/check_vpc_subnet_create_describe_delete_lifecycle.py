"""vpc-subnet-create-describe-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _delete_gone_ok(fn, gone_code):
    """Teardown: the body deletes the resource itself, so its not-found answer is done."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


CHECK = "vpc-subnet-create-describe-delete-lifecycle"
GROUP = 'vpc-subnet'
SERVICES = ['ec2']

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpc/CreateSubnet -> available; DeleteSubnet then DeleteVpc succeed once dependents are removed."""
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.1.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_gone_ok(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"] == "available":
            break
        time.sleep(2)

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.1.1.0/24", TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "sim2real", "Value": "1"}]}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_gone_ok(lambda: ec2.delete_subnet(SubnetId=subnet_id), "InvalidSubnetID.NotFound"))

    subnet = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
    assert subnet["VpcId"] == vpc_id, f"expected subnet in vpc {vpc_id}, got {subnet['VpcId']}"
    assert subnet["CidrBlock"] == "10.1.1.0/24", f"expected CidrBlock 10.1.1.0/24, got {subnet['CidrBlock']}"

    ec2.delete_subnet(SubnetId=subnet_id)
    try:
        ec2.describe_subnets(SubnetIds=[subnet_id])
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidSubnetID.NotFound", f"expected subnet gone, got {code}"
    assert message == f"The subnet ID '{subnet_id}' does not exist", f"unexpected message: {message!r}"

    ec2.delete_vpc(VpcId=vpc_id)
    try:
        ec2.describe_vpcs(VpcIds=[vpc_id])
        code = message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == "InvalidVpcID.NotFound", f"expected vpc gone, got {code}"
    assert message == f"The vpc ID '{vpc_id}' does not exist", f"unexpected message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
