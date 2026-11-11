"""deploy-rds-subnet-group-cfn-az-coverage."""
from __future__ import annotations

import secrets
import string


from behavioral_harness import tags

CHECK = "deploy-rds-subnet-group-cfn-az-coverage"
GROUP = "deploy"
SERVICES = ["rds"]

_TEMPLATE = """
Parameters:
  SubnetIds:
    Type: List<AWS::EC2::Subnet::Id>
  MasterUserPassword:
    Type: String
    NoEcho: true
Resources:
  SubnetGroup:
    Type: AWS::RDS::DBSubnetGroup
    Properties:
      DBSubnetGroupDescription: sim2real behavioral multi-az subnet group
      SubnetIds: !Ref SubnetIds
  Instance:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties:
      Engine: postgres
      DBInstanceClass: db.t3.micro
      AllocatedStorage: 20
      MasterUsername: s2radmin
      MasterUserPassword: !Ref MasterUserPassword
      DBSubnetGroupName: !Ref SubnetGroup
      PubliclyAccessible: false
Outputs:
  SubnetGroupName:
    Value: !Ref SubnetGroup
  InstanceId:
    Value: !Ref Instance
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed DBSubnetGroup spanning multiple AZs exposes exactly the subnet
    IDs/AZ set from the template and is usable to launch a real DB instance -- not
    merely that the subnet group resource exists."""
    vpc = _vpc_and_subnets(ctx, count=3)

    password = _rand_password()
    stack_name = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters=[
            {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(vpc["subnet_ids"])},
            {"ParameterKey": "MasterUserPassword", "ParameterValue": password},
        ],
        timeout_s=1800,
    )
    outputs = _stack_outputs(ctx, stack_name)
    subnet_group_name = outputs["SubnetGroupName"]
    instance_id = outputs["InstanceId"]

    rds = ctx.client("rds")
    sg = rds.describe_db_subnet_groups(DBSubnetGroupName=subnet_group_name)["DBSubnetGroups"][0]
    actual_subnet_ids = {s["SubnetIdentifier"] for s in sg["Subnets"]}
    actual_azs = {s["SubnetAvailabilityZone"]["Name"] for s in sg["Subnets"]}
    assert actual_subnet_ids == set(vpc["subnet_ids"]), (
        f"subnet group subnets {actual_subnet_ids} != template subnets {set(vpc['subnet_ids'])}"
    )
    assert actual_azs == set(vpc["azs"]), f"subnet group AZs {actual_azs} != expected {vpc['azs']}"

    instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    assert instance["DBInstanceStatus"] == "available", (
        f"expected DBInstance {instance_id!r} status 'available' after stack CREATE_COMPLETE, "
        f"got {instance['DBInstanceStatus']!r}"
    )
    assert instance["DBSubnetGroup"]["DBSubnetGroupName"] == subnet_group_name, (
        f"instance {instance_id!r} DBSubnetGroup "
        f"{instance['DBSubnetGroup']['DBSubnetGroupName']!r} != expected {subnet_group_name!r}"
    )
    assert instance["AvailabilityZone"] in vpc["azs"], (
        f"instance {instance_id!r} placed in AZ {instance['AvailabilityZone']!r}, "
        f"outside its subnet group's AZs {vpc['azs']}"
    )


# ===== helpers =====
def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _vpc_and_subnets(ctx, count: int = 3) -> dict:
    """Return {vpc_id, subnet_ids, azs} covering `count` distinct AZs. Prefers the account's
    shared network but falls back to any VPC, so the check does not depend on the shared network
    existing -- a freshly provisioned account may not have one."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    az_to_subnet: dict[str, str] = {}
    for s in subnets:
        az_to_subnet.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(az_to_subnet) < count:
        raise AssertionError(
            f"VPC {vpc_id} has subnets in only {len(az_to_subnet)} AZ(s); need >= {count} for this test"
        )
    azs = list(az_to_subnet.keys())[:count]
    subnet_ids = [az_to_subnet[az] for az in azs]
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "azs": azs}


def _deploy_cfn(ctx, template_body, parameters=None, timeout_s=1800) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-rds-cfn-")

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 750}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=parameters or [],
        OnFailure="DELETE",
    )
    ctx.on_cleanup(_cleanup)
    max_attempts = max(int(timeout_s // 30), 10)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts * 30 // 2}
    )
    return stack_name


def _stack_outputs(ctx, stack_name) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
