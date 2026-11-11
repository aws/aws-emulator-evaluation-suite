"""deploy-microsoft-ad-cloudformation-active."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

# Zone IDs where AWS Directory Service cannot place a directory. Zone names map to different
# zones in each account, so the zones are named by ID.
_DS_UNSUPPORTED_ZONE_IDS = {"usw2-az4", "use1-az3", "use1-az5", "cac1-az4"}

CHECK = "deploy-microsoft-ad-cloudformation-active"
GROUP = "deploy"
SERVICES = ["ds"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A AWS::DirectoryService::MicrosoftAD resource deployed via CloudFormation reaches
    Active stage and is independently queryable/consistent via DescribeDirectories and
    GetDirectoryLimits, not merely CREATE_COMPLETE on the stack."""
    net = _get_vpc_and_subnets(ctx)
    cfn = ctx.client("cloudformation")
    ds = ctx.client("ds")
    directory_name = _directory_name(ctx, "sim2realdscfn-")
    password = "Sim2Real!2024Pw"
    stack_name = ctx.unique_name("sim2real-ds-mad-stack-")

    template_body = json.dumps(
        {
            "Parameters": {
                "DirectoryName": {"Type": "String"},
                "DirectoryPassword": {"Type": "String", "NoEcho": True},
                "VpcId": {"Type": "AWS::EC2::VPC::Id"},
                "SubnetId1": {"Type": "AWS::EC2::Subnet::Id"},
                "SubnetId2": {"Type": "AWS::EC2::Subnet::Id"},
            },
            "Resources": {
                "MicrosoftAD": {
                    "Type": "AWS::DirectoryService::MicrosoftAD",
                    "Properties": {
                        "Name": {"Ref": "DirectoryName"},
                        "Password": {"Ref": "DirectoryPassword"},
                        "Edition": "Standard",
                        "VpcSettings": {
                            "VpcId": {"Ref": "VpcId"},
                            "SubnetIds": [{"Ref": "SubnetId1"}, {"Ref": "SubnetId2"}],
                        },
                    },
                }
            },
            "Outputs": {"DirectoryId": {"Value": {"Ref": "MicrosoftAD"}}},
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[
            {"ParameterKey": "DirectoryName", "ParameterValue": directory_name},
            {"ParameterKey": "DirectoryPassword", "ParameterValue": password},
            {"ParameterKey": "VpcId", "ParameterValue": net["vpc_id"]},
            {"ParameterKey": "SubnetId1", "ParameterValue": net["subnet_ids"][0]},
            {"ParameterKey": "SubnetId2", "ParameterValue": net["subnet_ids"][1]},
        ],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 2700})

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    directory_resource = next(
        r for r in resources if r["ResourceType"] == "AWS::DirectoryService::MicrosoftAD"
    )
    directory_id = directory_resource["PhysicalResourceId"]

    # CloudFormation's resource provider blocks create_stack until the directory itself
    # reaches Active, but we independently re-verify via DescribeDirectories rather than
    # trusting stack status alone.
    stage = _poll_until(
        lambda: ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0][
            "Stage"
        ],
        lambda s: s in ("Active", "Failed"),
        timeout_s=600,
        interval_s=15,
    )
    assert stage == "Active", f"directory reached terminal stage {stage!r}, not Active"

    described = ds.describe_directories(DirectoryIds=[directory_id])["DirectoryDescriptions"][0]
    assert described["Name"] == directory_name, (
        f"expected directory name {directory_name!r}, got {described['Name']!r}"
    )
    assert described["Type"] == "MicrosoftAD", f"expected type MicrosoftAD, got {described['Type']!r}"

    # The count is account-wide and other callers move it; while this check's directory exists
    # it counts at least that one.
    count = ds.get_directory_limits()["DirectoryLimits"]["CloudOnlyMicrosoftADCurrentCount"]
    assert count >= 1, (
        f"expected CloudOnlyMicrosoftADCurrentCount to count the Active directory {directory_id}, "
        f"got {count}"
    )


# ===== helpers =====
def _directory_name(ctx: Any, prefix: str) -> str:
    suffix = ctx.unique_name(prefix).rstrip("-")
    return f"{suffix}.test"


def _get_vpc_and_subnets(ctx: Any) -> dict[str, Any]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
            "Subnets"
        ]
        subnets = sorted((s for s in subnets if s.get("AvailabilityZoneId") not in _DS_UNSUPPORTED_ZONE_IDS), key=lambda s: s["AvailabilityZone"])
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return {"vpc_id": vpc_id, "subnet_ids": list(by_az.values())[:2]}

    name = ctx.unique_name("sim2real-ds-vpc-")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.91.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    azs = [az["ZoneName"] for az in ec2.describe_availability_zones()["AvailabilityZones"]][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.91.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}
            ],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids}


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s, last value: {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
