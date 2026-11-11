"""sdk-ssm-inventory-collects-ec2-metadata-positive."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sdk-ssm-inventory-collects-ec2-metadata-positive"
GROUP = "data-format"
SERVICES = ["cloudformation", "ec2", "ssm"]

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Running the AWS-GatherSoftwareInventory document on a real EC2 instance populates
    real instance metadata (platform, IP address, resource type) that is queryable back
    through ssm:GetInventory, scoped to that exact instance."""
    instance_profile = _ssm_instance_profile(ctx)
    ami_id = _latest_al2023_ami(ctx)
    instance_id = _launch_instance(ctx, ami_id, instance_profile_name=instance_profile, name_suffix="inventory")

    info = _wait_ssm_online(ctx, instance_id, timeout_s=300.0)
    if info is None:
        raise AssertionError(f"instance {instance_id} never registered Online with SSM")

    ssm = ctx.client("ssm")
    assoc = ssm.create_association(
        Name="AWS-GatherSoftwareInventory",
        Targets=[{"Key": "InstanceIds", "Values": [instance_id]}],
    )
    association_id = assoc["AssociationDescription"]["AssociationId"]
    ctx.on_cleanup(lambda: ssm.delete_association(AssociationId=association_id))

    ssm.start_associations_once(AssociationIds=[association_id])
    _wait_association_success(ctx, association_id, instance_id, timeout_s=300.0)

    entities = _poll_inventory(ctx, instance_id, timeout_s=180.0)
    content = entities[0]["Data"]["AWS:InstanceInformation"]["Content"][0]
    assert content["InstanceId"] == instance_id, (
        f"inventory scoped to {instance_id} returned InstanceId {content['InstanceId']!r}"
    )
    assert content["PlatformType"] == "Linux", f"expected PlatformType 'Linux', got {content['PlatformType']!r}"
    assert content["ResourceType"] == "EC2Instance", (
        f"expected ResourceType 'EC2Instance', got {content['ResourceType']!r}"
    )
    assert content["IpAddress"], "no IP address captured by inventory"


def _tag_spec(ctx, resource_type: str, name: str):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _latest_al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a test EC2 instance")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available")
    return subnets[0]["SubnetId"]


def _ssm_instance_profile(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ssm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    profile_name = ctx.unique_name("sim2real-ssm-profile-")
    iam.create_instance_profile(InstanceProfileName=profile_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=profile_name))
    iam.add_role_to_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=profile_name, RoleName=role_name)
    )
    deadline = time.monotonic() + 30.0
    while time.monotonic() < deadline:
        try:
            iam.get_instance_profile(InstanceProfileName=profile_name)
            break
        except Exception:
            time.sleep(2.0)
    return profile_name


def _launch_instance(ctx, ami_id: str, instance_profile_name: str | None = None, name_suffix: str = "instance"):
    ec2 = ctx.client("ec2")
    subnet_id = _default_subnet(ctx)
    kwargs = dict(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=_tag_spec(ctx, "instance", ctx.unique_name(f"sim2real-{name_suffix}-")),
    )
    if instance_profile_name:
        kwargs["IamInstanceProfile"] = {"Name": instance_profile_name}
    # A freshly created IAM instance profile can take longer to propagate to the EC2
    # control plane than to IAM itself; retry RunInstances on that specific error.
    deadline = time.monotonic() + 60.0
    resp = None
    while True:
        try:
            resp = ec2.run_instances(**kwargs)
            break
        except Exception as exc:
            if instance_profile_name and "InvalidParameterValue" in str(exc) and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    instance_id = resp["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return instance_id


def _wait_ssm_online(ctx, instance_id: str, timeout_s: float = 300.0, interval_s: float = 10.0):
    ssm = ctx.client("ssm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ssm.describe_instance_information(Filters=[{"Key": "InstanceIds", "Values": [instance_id]}])
        items = resp.get("InstanceInformationList", [])
        if items and items[0].get("PingStatus") == "Online":
            return items[0]
        time.sleep(interval_s)
    return None


def _poll_inventory(ctx, instance_id: str, timeout_s: float = 180.0, interval_s: float = 10.0):
    ssm = ctx.client("ssm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = ssm.get_inventory(
            Filters=[{"Key": "AWS:InstanceInformation.InstanceId", "Values": [instance_id], "Type": "Equal"}],
        )
        entities = resp.get("Entities", [])
        if entities and entities[0].get("Data", {}).get("AWS:InstanceInformation", {}).get("Content"):
            return entities
        time.sleep(interval_s)
    raise AssertionError("inventory for the instance never became queryable via get_inventory")


def _wait_association_success(
    ctx, association_id: str, instance_id: str, timeout_s: float = 300.0, interval_s: float = 10.0
):
    ssm = ctx.client("ssm")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        desc = ssm.describe_association(AssociationId=association_id)["AssociationDescription"]
        last_status = desc.get("Overview", {}).get("Status")
        if last_status == "Success":
            return
        if last_status == "Failed":
            raise AssertionError(f"association {association_id} failed on instance {instance_id}")
        time.sleep(interval_s)
    raise AssertionError(f"association {association_id} never reached Success (last status: {last_status!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
