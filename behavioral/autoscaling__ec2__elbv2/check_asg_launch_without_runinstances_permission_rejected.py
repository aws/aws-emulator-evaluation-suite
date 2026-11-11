"""asg-launch-without-runinstances-permission-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "asg-launch-without-runinstances-permission-rejected"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ec2", "elbv2"]

_PREFIX = "sim2real-asg-"


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAutoScalingGroup with a launch template synchronously checks whether the caller is
    authorized to use it (which requires ec2:RunInstances) and rejects a caller who lacks it with
    AccessDenied -- no group is created -- but succeeds once that single permission is granted.
    """
    vpc_id, subnet_id = _default_subnet(ctx)
    sg_id = _create_security_group(ctx, vpc_id)
    ami_id = _latest_al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id, sg_id)

    describe_only_actions = [
        "autoscaling:CreateAutoScalingGroup",
        "autoscaling:DescribeAutoScalingGroups",
        "autoscaling:UpdateAutoScalingGroup",
        "autoscaling:DeleteAutoScalingGroup",
        "ec2:DescribeInstances",
        "ec2:DescribeLaunchTemplates",
        "ec2:DescribeLaunchTemplateVersions",
        "ec2:DescribeSubnets",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeImages",
    ]
    principal = _create_restricted_principal(ctx, describe_only_actions)
    _wait_for_credentials_active(ctx, principal)

    restricted_asg = _client_with_credentials(ctx, principal, "autoscaling")

    # Warm-up: make sure the granted (autoscaling Describe*) permissions have propagated
    # before we rely on absence of ec2:RunInstances to be the cause of the failure below.
    _wait_for_authz(lambda: restricted_asg.describe_auto_scaling_groups(MaxRecords=1))

    blocked_name = ctx.unique_name(f"{_PREFIX}blocked-")
    code, message = _error(
        lambda: restricted_asg.create_auto_scaling_group(
            AutoScalingGroupName=blocked_name,
            LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
            MinSize=1,
            MaxSize=1,
            DesiredCapacity=1,
            VPCZoneIdentifier=subnet_id,
            Tags=[{"Key": "sim2real", "Value": "true", "PropagateAtLaunch": False}],
        )
    )
    assert code == "AccessDenied", f"expected AccessDenied, got {code!r}"
    expected_message = f"You are not authorized to use launch template: {lt_id}"
    assert message == expected_message, f"AccessDenied message {message!r}, expected {expected_message!r}"

    # Effect absent: the group must never have been created.
    admin_asg = ctx.client("autoscaling")
    groups = admin_asg.describe_auto_scaling_groups(AutoScalingGroupNames=[blocked_name])["AutoScalingGroups"]
    assert groups == [], "an ASG must not exist after a permission-validation failure at creation time"

    # Positive control: grant exactly ec2:RunInstances to the SAME restricted principal and
    # retry -- isolating that this one permission was the sole blocking condition.
    iam = ctx.client("iam")
    iam.put_user_policy(
        UserName=principal["user_name"],
        PolicyName=principal["policy_name"],
        PolicyDocument=json.dumps(_policy_document(describe_only_actions + ["ec2:RunInstances"])),
    )

    allowed_name = ctx.unique_name(f"{_PREFIX}allowed-")

    def _create_allowed():
        restricted_asg.create_auto_scaling_group(
            AutoScalingGroupName=allowed_name,
            LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
            MinSize=1,
            MaxSize=1,
            DesiredCapacity=1,
            VPCZoneIdentifier=subnet_id,
            Tags=[{"Key": "sim2real", "Value": "true", "PropagateAtLaunch": False}],
        )

    _wait_for_authz(_create_allowed)
    ctx.on_cleanup(lambda: _terminate_asg_and_wait(ctx, allowed_name))

    ids = _wait_for_in_service_count(ctx, allowed_name, 1, timeout_s=150)
    assert len(ids) == 1, f"expected exactly 1 InService instance once ec2:RunInstances was granted, got {ids!r}"


def _policy_document(actions):
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": actions, "Resource": "*"}],
    }


def _create_restricted_principal(ctx, allowed_actions):
    iam = ctx.client("iam")
    user_name = ctx.unique_name(f"{_PREFIX}restricted-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": "true"}])
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))

    policy_name = "sim2real-inline-policy"
    iam.put_user_policy(
        UserName=user_name, PolicyName=policy_name, PolicyDocument=json.dumps(_policy_document(allowed_actions))
    )
    ctx.on_cleanup(lambda: iam.delete_user_policy(UserName=user_name, PolicyName=policy_name))

    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    return {
        "user_name": user_name,
        "policy_name": policy_name,
        "access_key_id": key["AccessKeyId"],
        "secret_access_key": key["SecretAccessKey"],
    }


def _client_with_credentials(ctx, principal, service):
    """A client signing AS the restricted principal against the same target ctx.client() uses."""
    return ctx.client(service, creds={
        "aws_access_key_id": principal["access_key_id"],
        "aws_secret_access_key": principal["secret_access_key"],
    })


def _wait_for_credentials_active(ctx, principal, timeout_s=60, interval_s=5):
    deadline = time.monotonic() + timeout_s
    last_err = None
    sts = _client_with_credentials(ctx, principal, "sts")
    while time.monotonic() < deadline:
        try:
            sts.get_caller_identity()
            return
        except ClientError as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"restricted IAM credentials never became active: {last_err}")


def _wait_for_authz(fn, timeout_s=90, interval_s=10):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("AccessDenied", "AccessDeniedException", "ValidationError"):
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"call never authorized within {timeout_s}s (IAM propagation): {last_err}")


def _error(fn):
    """The captured AWS error (code, message). An unexpected SUCCESS raises rather than returning a
    falsy sentinel."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected AccessDenied, but the call SUCCEEDED and returned {result!r}")


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region; use the run's shared network (or wire a "
            "dedicated test VPC/subnet) to close this gap"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no network subnets; create one to close this gap")
    return vpc_id, subnets[0]["SubnetId"]


def _latest_al2023_ami(ctx):
    ec2 = ctx.client("ec2")
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI visible to this account/region to launch test instances")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _create_security_group(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"{_PREFIX}sg-")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral test sg",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "sim2real", "Value": "true"}]}
        ],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    return sg_id


def _create_launch_template(ctx, ami_id, sg_id, instance_type="t3.micro"):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"{_PREFIX}lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "SecurityGroupIds": [sg_id],
        },
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "true"}]}
        ],
    )["LaunchTemplate"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt["LaunchTemplateId"]))
    return lt["LaunchTemplateId"]


def _terminate_asg_and_wait(ctx, name, timeout_s=420):
    """Force-delete the group, then wait until it and its instances are gone: a refusal while a
    scaling activity runs is retried every 2 s, a group already gone is done, anything else raises."""
    from botocore.exceptions import ClientError

    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ids = _group_instance_ids(ctx, name)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                break
            busy = ("ScalingActivityInProgress", "ResourceInUse", "ResourceContention")
            if err["Code"] not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]:
        if time.monotonic() >= deadline:
            raise TimeoutError(f"auto scaling group {name} still listed at the teardown deadline")
        time.sleep(2)
    if ids:
        deadline = time.monotonic() + timeout_s
        while True:
            resp = ec2.describe_instances(InstanceIds=ids)
            states = {i["State"]["Name"] for r in resp["Reservations"] for i in r["Instances"]}
            if states <= {"terminated"}:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError(f"instances {ids} of {name} not terminated: {states}")
            time.sleep(2)


def _group_instance_ids(ctx, name, lifecycle_states=None):
    asg = ctx.client("autoscaling")
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    if not groups:
        return []
    instances = groups[0]["Instances"]
    if lifecycle_states:
        instances = [i for i in instances if i["LifecycleState"] in lifecycle_states]
    return [i["InstanceId"] for i in instances]


def _wait_for_in_service_count(ctx, name, count, timeout_s=600, interval_s=15):
    deadline = time.monotonic() + timeout_s
    last = -1
    while time.monotonic() < deadline:
        ids = _group_instance_ids(ctx, name, lifecycle_states=("InService",))
        last = len(ids)
        if last == count:
            return ids
        time.sleep(interval_s)
    raise AssertionError(f"expected {count} InService instances, saw {last} after {timeout_s}s")



def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
