"""deploy-db-subnet-group-cfn-instance-placement."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-db-subnet-group-cfn-instance-placement"
GROUP = "deploy"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::RDS::DBSubnetGroup restricted to a specific 2-AZ subset
    actually confines the instance created against it to those AZs — the subnet group is
    enforced at placement time, not merely accepted and ignored."""
    vpc_id, az_subnets = _pick_azs_with_subnets(ctx, count=2)
    subnet_ids = [s["SubnetId"] for s in az_subnets]
    chosen_azs = {s["AvailabilityZone"] for s in az_subnets}
    user = "s2radmin"
    password = _master_password()

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "SubnetIds": {"Type": "List<AWS::EC2::Subnet::Id>"},
            "MasterUsername": {"Type": "String", "NoEcho": True},
            "MasterPassword": {"Type": "String", "NoEcho": True},
        },
        "Resources": {
            "DBSubnetGroup": {
                "Type": "AWS::RDS::DBSubnetGroup",
                "Properties": {
                    "DBSubnetGroupDescription": "sim2real behavioral placement test (2 AZs only)",
                    "SubnetIds": {"Ref": "SubnetIds"},
                },
            },
            "DBInstance": {
                "Type": "AWS::RDS::DBInstance",
                "DeletionPolicy": "Delete",
                "Properties": {
                    "Engine": "postgres",
                    "DBInstanceClass": "db.t3.micro",
                    "AllocatedStorage": "20",
                    "MasterUsername": {"Ref": "MasterUsername"},
                    "MasterUserPassword": {"Ref": "MasterPassword"},
                    "DBSubnetGroupName": {"Ref": "DBSubnetGroup"},
                    "PubliclyAccessible": False,
                    "BackupRetentionPeriod": 1,
                },
            },
        },
        "Outputs": {
            "DBInstanceIdentifier": {"Value": {"Ref": "DBInstance"}},
            "DBSubnetGroupName": {"Value": {"Ref": "DBSubnetGroup"}},
        },
    }

    outputs = _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters=[
            {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(subnet_ids)},
            {"ParameterKey": "MasterUsername", "ParameterValue": user},
            {"ParameterKey": "MasterPassword", "ParameterValue": password},
        ],
        timeout_s=2400,
    )

    rds = ctx.client("rds")
    instance_id = outputs["DBInstanceIdentifier"]
    subnet_group_name = outputs["DBSubnetGroupName"]

    desc = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    assert desc["DBInstanceStatus"] == "available", (
        f"expected 'available' after stack CREATE_COMPLETE, got {desc['DBInstanceStatus']!r}"
    )
    placed_az = desc["AvailabilityZone"]

    subnet_group = rds.describe_db_subnet_groups(DBSubnetGroupName=subnet_group_name)[
        "DBSubnetGroups"
    ][0]
    group_azs = {s["SubnetAvailabilityZone"]["Name"] for s in subnet_group["Subnets"]}

    # The subnet group must actually be restricted to exactly the 2 AZs we gave it (not silently
    # expanded to every AZ in the VPC/region by an unfaithful emulator)...
    assert group_azs == chosen_azs, (
        f"DBSubnetGroup {subnet_group_name} covers {group_azs}, expected exactly {chosen_azs}"
    )
    # ...and the instance created against it must be placed inside that restricted set, not just
    # anywhere in the region.
    assert placed_az in group_azs, (
        f"instance {instance_id} was placed in AZ {placed_az!r}, outside its DBSubnetGroup's "
        f"AZs {group_azs} — the subnet group was accepted but not enforced at placement time"
    )


# ===== helpers =====

def _master_password() -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "Sim2Real1" + "".join(secrets.choice(alphabet) for _ in range(12))


def _pick_azs_with_subnets(ctx, count: int = 2) -> tuple[str, list[dict]]:
    """Return (vpc_id, [subnet, ...]) covering `count` distinct AZs, for a DBSubnetGroup.
    Adopts the shared network's subnets when they cover enough AZs; otherwise creates a
    throwaway VPC + subnets, so the check does not depend on an ambient shared network that a
    freshly provisioned account may not have."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, dict] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    if len(by_az) >= count:
        return vpc_id, list(by_az.values())[:count]
    return _create_vpc_with_subnets(ctx, count)


def _create_vpc_with_subnets(ctx, count: int) -> tuple[str, list[dict]]:
    """Create a throwaway VPC with `count` subnets in distinct AZs, torn down on cleanup."""
    ec2 = ctx.client("ec2")
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "state", "Values": ["available"]},
                {"Name": "zone-type", "Values": ["availability-zone"]},
            ]
        )["AvailabilityZones"]
    ][:count]
    if len(azs) < count:
        raise AssertionError(
            f"region {ctx.region} has only {len(azs)} available AZ(s); need >= {count} for an "
            "RDS subnet group"
        )
    vpc_id = ec2.create_vpc(CidrBlock="10.212.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    subnets = []
    for i, az in enumerate(azs):
        subnet = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.212.{i}.0/24", AvailabilityZone=az
        )["Subnet"]
        ctx.on_cleanup(lambda sid=subnet["SubnetId"]: ec2.delete_subnet(SubnetId=sid))
        subnets.append(subnet)
    return vpc_id, subnets


def _deploy_cfn(ctx, template_body: str, parameters: list[dict[str, str]] | None = None,
                 timeout_s: int = 2400) -> dict[str, str]:
    """Create a CloudFormation stack, poll to CREATE_COMPLETE, return its Outputs. Registers
    stack-delete cleanup (waits for DELETE_COMPLETE)."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-rds-cfn-")
    kwargs: dict[str, Any] = {"StackName": stack_name, "TemplateBody": template_body}
    if parameters:
        kwargs["Parameters"] = parameters

    def _cleanup() -> None:
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 750})

    cfn.create_stack(**kwargs)
    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + timeout_s
    while True:
        desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
        status = desc["StackStatus"]
        if status == "CREATE_COMPLETE":
            return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
        if status.endswith("FAILED") or "ROLLBACK" in status:
            events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
            reasons = [
                e.get("ResourceStatusReason", "")
                for e in events
                if "FAILED" in e.get("ResourceStatus", "")
            ]
            raise AssertionError(f"stack {stack_name} entered {status}: {reasons}")
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {stack_name} did not reach CREATE_COMPLETE within {timeout_s}s "
                f"(status={status})"
            )
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
