"""deploy-cfn-subnet-group-drives-instance-placement."""
from __future__ import annotations

import secrets
import string
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-subnet-group-drives-instance-placement"
GROUP = "deploy"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DBSubnetGroup and dependent DBInstance deployed together via CFN result
    in the instance's subnet group membership matching the declared subnet list
    exactly."""
    subnet_ids = _pick_two_az_subnets(ctx)
    subnet_group_name = ctx.unique_name("sim2real-rds-sng-")
    instance_id = ctx.unique_name("sim2real-rds-sginst-")
    password = _gen_password()
    subnet_ids_yaml = "\n".join(f"        - {sid}" for sid in subnet_ids)

    template = f"""AWSTemplateFormatVersion: '2010-09-09'
Resources:
  SubnetGroup:
    Type: AWS::RDS::DBSubnetGroup
    Properties:
      DBSubnetGroupName: {subnet_group_name}
      DBSubnetGroupDescription: sim2real placement check
      SubnetIds:
{subnet_ids_yaml}
      Tags:
        - Key: sim2real:managed
          Value: "true"
  DBInstance:
    Type: AWS::RDS::DBInstance
    DeletionPolicy: Delete
    Properties:
      DBInstanceIdentifier: {instance_id}
      Engine: mysql
      DBInstanceClass: db.t3.micro
      AllocatedStorage: 20
      MasterUsername: sim2realadmin
      MasterUserPassword: {password}
      DBSubnetGroupName: !Ref SubnetGroup
      BackupRetentionPeriod: 0
      PubliclyAccessible: false
      Tags:
        - Key: sim2real:managed
          Value: "true"
"""
    _deploy_cfn_stack(ctx, template)

    rds = ctx.client("rds")
    sg = rds.describe_db_subnet_groups(DBSubnetGroupName=subnet_group_name)["DBSubnetGroups"][0]
    sg_subnets = {s["SubnetIdentifier"] for s in sg["Subnets"]}
    assert sg_subnets == set(subnet_ids), sg_subnets

    instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    inst_subnets = {s["SubnetIdentifier"] for s in instance["DBSubnetGroup"]["Subnets"]}
    assert inst_subnets == set(subnet_ids), inst_subnets


def _gen_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


def _pick_two_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to source subnets for the placement check")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            "shared network VPC does not span at least 2 AZs; cannot exercise DBSubnetGroup placement"
        )
    return list(by_az.values())[:2]


def _deploy_cfn_stack(ctx, template_body: str, timeout_s: int = 1800) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-rds-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_stack_status(ctx, stack_name, {"CREATE_COMPLETE"}, timeout_s)
    return stack_name


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _wait_stack_status(ctx, stack_name, {"DELETE_COMPLETE"}, 1800, allow_not_found=True)


def _wait_stack_status(ctx, stack_name, ok_statuses, timeout_s, allow_not_found=False):
    cfn = ctx.client("cloudformation")
    bad_statuses = {
        "CREATE_FAILED", "ROLLBACK_IN_PROGRESS", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
        "UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
        "DELETE_FAILED", "UPDATE_FAILED",
    } - set(ok_statuses)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except Exception:
            if allow_not_found:
                return "DELETE_COMPLETE"
            raise
        status = resp["Stacks"][0]["StackStatus"]
        if status in ok_statuses:
            return status
        if status in bad_statuses:
            raise AssertionError(f"stack {stack_name} reached unexpected status {status}")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not reach {ok_statuses} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
