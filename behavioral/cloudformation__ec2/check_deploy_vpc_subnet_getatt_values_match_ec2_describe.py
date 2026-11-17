"""deploy-vpc-subnet-getatt-values-match-ec2-describe."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-vpc-subnet-getatt-values-match-ec2-describe"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

_TAGS = [{"Key": "sim2real", "Value": "deploy-vpc-subnet-getatt"}]


def _template() -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": "10.42.0.0/16", "Tags": _TAGS}},
            "Subnet": {"Type": "AWS::EC2::Subnet", "Properties": {
                "VpcId": {"Ref": "Vpc"}, "CidrBlock": "10.42.1.0/24",
                "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]}, "Tags": _TAGS}},
        },
        "Outputs": {
            "VpcRef": {"Value": {"Ref": "Vpc"}},
            "VpcId": {"Value": {"Fn::GetAtt": ["Vpc", "VpcId"]}},
            "VpcCidr": {"Value": {"Fn::GetAtt": ["Vpc", "CidrBlock"]}},
            "VpcAssociations": {"Value": {"Fn::Join": [",", {"Fn::GetAtt": ["Vpc", "CidrBlockAssociations"]}]}},
            "VpcIpv6": {"Value": {"Fn::Join": [",", {"Fn::GetAtt": ["Vpc", "Ipv6CidrBlocks"]}]}},
            "VpcNacl": {"Value": {"Fn::GetAtt": ["Vpc", "DefaultNetworkAcl"]}},
            "VpcSg": {"Value": {"Fn::GetAtt": ["Vpc", "DefaultSecurityGroup"]}},
            "SubnetRef": {"Value": {"Ref": "Subnet"}},
            "SubnetId": {"Value": {"Fn::GetAtt": ["Subnet", "SubnetId"]}},
            "SubnetCidr": {"Value": {"Fn::GetAtt": ["Subnet", "CidrBlock"]}},
            "SubnetAz": {"Value": {"Fn::GetAtt": ["Subnet", "AvailabilityZone"]}},
            "SubnetAzId": {"Value": {"Fn::GetAtt": ["Subnet", "AvailabilityZoneId"]}},
            "SubnetNaclAssoc": {"Value": {"Fn::GetAtt": ["Subnet", "NetworkAclAssociationId"]}},
            "SubnetVpc": {"Value": {"Fn::GetAtt": ["Subnet", "VpcId"]}},
        },
    })


def _wait(cf, stack_id: str, budget_s: float = 600.0) -> dict:
    """The stack once it leaves every *_IN_PROGRESS state."""
    deadline = time.monotonic() + budget_s
    while True:
        stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
        if not stack["StackStatus"].endswith("_IN_PROGRESS"):
            return stack
        if time.monotonic() > deadline:
            raise AssertionError(f"stack still {stack['StackStatus']!r} after {budget_s}s")
        time.sleep(4)


def _delete_stack(cf, stack_id: str):
    """A cleanup that deletes the stack and raises unless it reaches DELETE_COMPLETE."""

    def run_delete() -> None:
        cf.delete_stack(StackName=stack_id)
        status = _wait(cf, stack_id)["StackStatus"]
        if status != "DELETE_COMPLETE":
            raise AssertionError(f"stack delete ended {status!r}")

    return run_delete


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every Fn::GetAtt a VPC and a subnet document resolves to the value EC2 itself reports for them:
    CIDRs, the CIDR association, the default network ACL and security group, AZ, AZ id and ACL link."""
    cf = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-netatt-")
    stack_id = cf.create_stack(StackName=name, TemplateBody=_template(),
                               Tags=[{"Key": "sim2real", "Value": name}])["StackId"]
    ctx.on_cleanup(_delete_stack(cf, stack_id))
    stack = _wait(cf, stack_id)
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"create ended {stack['StackStatus']!r}"
    out = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}

    vpc_id = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Vpc")[
        "StackResourceDetail"]["PhysicalResourceId"]
    subnet_id = cf.describe_stack_resource(StackName=stack_id, LogicalResourceId="Subnet")[
        "StackResourceDetail"]["PhysicalResourceId"]
    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    subnet = ec2.describe_subnets(SubnetIds=[subnet_id])["Subnets"][0]
    acls = ec2.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                                             {"Name": "default", "Values": ["true"]}])["NetworkAcls"]
    assert len(acls) == 1, f"{len(acls)} default network ACLs in the stack's VPC"
    groups = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]},
                                                   {"Name": "group-name", "Values": ["default"]}])
    groups = groups["SecurityGroups"]
    assert len(groups) == 1, f"{len(groups)} default security groups in the stack's VPC"
    links = [a for a in acls[0]["Associations"] if a["SubnetId"] == subnet_id]
    assert len(links) == 1, f"{len(links)} default-ACL associations for the stack's subnet"

    expected = {
        "VpcRef": vpc_id,
        "VpcId": vpc_id,
        "VpcCidr": "10.42.0.0/16",
        "VpcAssociations": ",".join(a["AssociationId"] for a in vpc["CidrBlockAssociationSet"]),
        "VpcIpv6": "",
        "VpcNacl": acls[0]["NetworkAclId"],
        "VpcSg": groups[0]["GroupId"],
        "SubnetRef": subnet_id,
        "SubnetId": subnet_id,
        "SubnetCidr": "10.42.1.0/24",
        "SubnetAz": subnet["AvailabilityZone"],
        "SubnetAzId": subnet["AvailabilityZoneId"],
        "SubnetNaclAssoc": links[0]["NetworkAclAssociationId"],
        "SubnetVpc": vpc_id,
    }
    wrong = {k: (out.get(k), v) for k, v in expected.items() if out.get(k) != v}
    assert not wrong, f"outputs differing from EC2 (output, ec2): {wrong!r}"
    assert sorted(out) == sorted(expected), f"output keys {sorted(out)!r}"
    assert vpc["CidrBlock"] == "10.42.0.0/16", f"EC2 VPC CidrBlock {vpc['CidrBlock']!r}"
    assert subnet["CidrBlock"] == "10.42.1.0/24", f"EC2 subnet CidrBlock {subnet['CidrBlock']!r}"
    assert subnet["VpcId"] == vpc_id, "EC2 places the subnet in another VPC"
    zones = [z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "zone-type", "Values": ["availability-zone"]}])["AvailabilityZones"]]
    assert subnet["AvailabilityZone"] in zones, (
        f"subnet AZ {subnet['AvailabilityZone']!r} is not one of the region's zones {zones!r}"
    )

    cf.delete_stack(StackName=stack_id)
    assert _wait(cf, stack_id)["StackStatus"] == "DELETE_COMPLETE", "stack delete did not complete"
    remaining = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["Vpcs"]
    assert remaining == [], f"the VPC outlived its stack: {len(remaining)} found"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
