"""asg-launched-instance-boots-and-writes-its-own-identity."""

from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asg-launched-instance-boots-and-writes-its-own-identity"
GROUP = "instance-lifecycle"
SERVICES = ["autoscaling", "ec2", "s3"]


@tags(
    "axis:happy-path",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """The ASG-launched instance really boots: it writes the instance id it read from IMDSv2 to S3,
    and that id matches the group's member and EC2's view; the bounded S3 poll fails if it never
    appears, since a provisioned-but-never-booted instance is the defect this catches."""
    marker = ctx.unique_name("sim2real-xsvc-boot-")
    bucket = _bucket(ctx)
    role, profile = _instance_profile(ctx, bucket, key_prefix="*")
    _vpc, subnets = _usable_subnets(ctx, "t3.micro", want=2)
    sg_id = _egress_only_sg(ctx, _vpc)

    user_data = (
        "#!/bin/bash\n"
        "set -x\n"
        'TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" '
        '-H "X-aws-ec2-metadata-token-ttl-seconds: 300")\n'
        'IID=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" '
        "http://169.254.169.254/latest/meta-data/instance-id)\n"
        "printf '%s' \"$IID\" > /tmp/iid\n"
        f"aws s3api put-object --bucket {bucket} --key {marker}/id --body /tmp/iid "
        f"--region {ctx.region}\n"
    )
    lt_name = _launch_template(
        ctx, _al2023_ami(ctx), user_data=user_data, sg_ids=[sg_id], profile=profile
    )
    name = _create_asg(ctx, lt_name, subnets, min_size=1, max_size=1, desired=1)

    instance = _poll(
        lambda: _members(ctx, name),
        lambda ms: (
            len(ms) == 1
            and ms[0]["LifecycleState"] == "InService"
            and ms[0]["HealthStatus"] == "Healthy"
        ),
        ctx=ctx,
        timeout_s=_budget_s(ctx, 1200),
        interval_s=2,
        description="the ASG reported one InService/Healthy instance",
    )[0]
    asg_instance_id = instance["InstanceId"]
    lifecycle = instance["LifecycleState"]
    assert lifecycle == "InService", (
        f"the instance never reached InService: {lifecycle!r}"
    )

    body = _poll(
        lambda: _get_object(ctx, bucket, f"{marker}/id"),
        lambda b: b is not None,
        ctx=ctx,
        timeout_s=_budget_s(ctx, 900),
        interval_s=2,
        description=f"the launched instance wrote s3://{bucket}/{marker}/id from its UserData",
    )
    assert body is not None, (
        f"no object appeared at s3://{bucket}/{marker}/id -- the ASG reported InService for an "
        f"instance whose UserData never ran"
    )
    written = body.strip()
    assert written.startswith("i-"), (
        f"the UserData did not produce an instance id: {body!r}"
    )
    assert written == asg_instance_id, (
        f"the object the instance wrote names a different instance than the ASG reports: "
        f"{written!r} != {asg_instance_id!r}"
    )
    state = _instance(ctx, asg_instance_id)["State"]
    assert state["Name"] == "running", (
        f"the ASG reported InService for an instance that is not running: {state!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = {"sim2real": "as-boot", "sim2real:managed": "true"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown
        pass


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(fn, pred, *, timeout_s, interval_s=2, description="condition", ctx=None):
    """Poll fn() until pred() holds; raise with the last observed value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(
                f"{description} not met within {timeout_s}s; last={last!r}"
            )
        time.sleep(interval_s)
        last = fn()
    return last


def _al2023_ami(ctx) -> str:
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    value = ctx.client("ssm").get_parameter(Name=param)["Parameter"]["Value"]
    assert value.startswith("ami-"), f"{param} did not resolve to an AMI: {value!r}"
    return value


def _usable_subnets(ctx, instance_type: str, want: int = 1):
    """Default-VPC subnets in AZs that ACTUALLY OFFER instance_type.

    The shared network is used deliberately: its subnets already have an internet-gateway route and
    auto-assign a public IP, so the instance can reach the S3 endpoint with no NAT gateway and no
    EIP left behind if teardown is interrupted.
    """
    ec2 = ctx.client("ec2")
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    }
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region to launch instances into"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = []
    for page in ec2.get_paginator("describe_subnets").paginate(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids},
        ]
    ):
        subnets += page["Subnets"]
    per_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["SubnetId"]):
        if (
            sn["AvailabilityZone"] in (offered & available)
            and sn.get("AvailableIpAddressCount", 0) > 0
            and sn.get("MapPublicIpOnLaunch")
        ):
            per_az.setdefault(sn["AvailabilityZone"], sn["SubnetId"])
    ids = [per_az[az] for az in sorted(per_az)]
    assert len(ids) >= want, (
        f"need {want} public shared-network subnets in AZs offering {instance_type!r}, found {ids!r}; "
        f"offered={sorted(offered)!r}, available={sorted(available)!r}"
    )
    return vpc_id, ids[:want]


def _egress_only_sg(ctx, vpc_id: str) -> str:
    """A security group with NO ingress -- the instance only needs to reach OUT to S3. Created
    FIRST so its LIFO teardown runs LAST: an ENI keeps the group referenced for a while after the
    instance is gone, so the delete is retried on a bounded loop."""
    ec2 = ctx.client("ec2")
    gid = ec2.create_security_group(
        GroupName=ctx.unique_name(_XSVC_PREFIX + "sg-"),
        Description="sim2real asg boot proof, egress only",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv()}],
    )["GroupId"]

    def _drop():
        for _ in range(120):
            try:
                ec2.delete_security_group(GroupId=gid)
                return
            except Exception:  # noqa: BLE001 - ENI still detaching
                time.sleep(2)
        raise RuntimeError(f"security group {gid} could not be deleted")

    ctx.on_cleanup(_drop)
    return gid


def _bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(_XSVC_PREFIX + "boot-")
    kwargs = {"Bucket": name}
    if (
        ctx.region != "us-east-1"
    ):  # CreateBucket rejects an explicit LocationConstraint there
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _drop():
        # Paginated: the instance may have written more than one object, and a non-empty bucket
        # cannot be deleted.
        try:
            for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
                for obj in page.get("Contents", []):
                    _swallow(lambda k=obj["Key"]: s3.delete_object(Bucket=name, Key=k))
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        _swallow(lambda: s3.delete_bucket(Bucket=name))

    ctx.on_cleanup(_drop)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _tags_kv()})
    return name


def _instance_profile(ctx, bucket: str, *, key_prefix: str) -> tuple[str, str]:
    """(role, instance profile) letting the instance PutObject under bucket/<key_prefix>.

    IAM exposes no API that reports a policy has become effective. Instance-profile propagation
    into IAM's own PassRole check is bounded by the retry in _create_asg (CreateAutoScalingGroup
    rejects the launch template's instance profile SYNCHRONOUSLY, with no async retry to lean on);
    propagation into the actual PutObject permission the instance uses at runtime is bounded by the
    bounded S3 poll in run().
    """
    iam = ctx.client("iam")
    role = ctx.unique_name(_XSVC_PREFIX + "role-")
    profile = ctx.unique_name(_XSVC_PREFIX + "prof-")
    iam.create_role(
        RoleName=role,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Description="sim2real asg boot proof",
        Tags=_tags_kv(),
    )
    iam.create_instance_profile(InstanceProfileName=profile, Tags=_tags_kv())

    def _drop():
        _swallow(
            lambda: iam.remove_role_from_instance_profile(
                InstanceProfileName=profile, RoleName=role
            )
        )
        _swallow(lambda: iam.delete_instance_profile(InstanceProfileName=profile))
        _swallow(lambda: iam.delete_role_policy(RoleName=role, PolicyName="s3-put"))
        _swallow(lambda: iam.delete_role(RoleName=role))

    ctx.on_cleanup(_drop)
    iam.put_role_policy(
        RoleName=role,
        PolicyName="s3-put",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket}/{key_prefix}",
                    }
                ],
            }
        ),
    )
    iam.add_role_to_instance_profile(InstanceProfileName=profile, RoleName=role)
    _poll(
        lambda: iam.get_instance_profile(InstanceProfileName=profile)[
            "InstanceProfile"
        ]["Roles"],
        lambda roles: [r["RoleName"] for r in roles] == [role],
        ctx=ctx,
        timeout_s=_budget_s(ctx, 120),
        interval_s=2,
        description=f"instance profile {profile} reports role {role}",
    )
    # IAM propagation beyond this point is bounded by the ASG's own launch retry loop plus the
    # InService/S3 polls in run() -- not by a fixed sleep here.
    return role, profile


def _launch_template(
    ctx,
    ami: str,
    *,
    user_data: str,
    sg_ids,
    profile: str,
    instance_type: str = "t3.micro",
) -> str:
    """A launch template tagging BOTH the instance and its volume AT LAUNCH, and forcing IMDSv2 --
    the UserData reads its identity through the token endpoint."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(_XSVC_PREFIX + "lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami,
            "InstanceType": instance_type,
            "UserData": base64.b64encode(user_data.encode("utf-8")).decode("ascii"),
            "SecurityGroupIds": list(sg_ids),
            "IamInstanceProfile": {"Name": profile},
            "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
            "TagSpecifications": [
                {"ResourceType": "instance", "Tags": _tags_kv()},
                {"ResourceType": "volume", "Tags": _tags_kv()},
            ],
        },
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
    )

    def _drop():
        for _ in range(60):
            try:
                ec2.delete_launch_template(LaunchTemplateName=name)
                return
            except Exception:  # noqa: BLE001 - still referenced by a deleting ASG
                time.sleep(2)
        raise RuntimeError(f"launch template {name} could not be deleted")

    ctx.on_cleanup(_drop)
    return name


def _create_asg(
    ctx, lt_name: str, subnets, *, min_size: int, max_size: int, desired: int, **kwargs
) -> str:
    asg = ctx.client("autoscaling")
    name = ctx.unique_name(_XSVC_PREFIX + "asg-")
    params = {
        "AutoScalingGroupName": name,
        "LaunchTemplate": {"LaunchTemplateName": lt_name, "Version": "$Latest"},
        "MinSize": min_size,
        "MaxSize": max_size,
        "DesiredCapacity": desired,
        "VPCZoneIdentifier": ",".join(subnets),
        "HealthCheckGracePeriod": 120,
        "Tags": [
            {"Key": k, "Value": v, "PropagateAtLaunch": True}
            for k, v in _MANAGED_TAGS.items()
        ],
    }
    params.update(kwargs)
    # CreateAutoScalingGroup resolves the launch template's IAM instance profile SYNCHRONOUSLY and
    # rejects it with ValidationError while the profile is still propagating through IAM -- unlike an
    # instance launch, there is no async retry loop to lean on here, so this call gets its own bounded
    # retry, scoped to that one message.
    deadline = time.monotonic() + 120
    while True:
        try:
            asg.create_auto_scaling_group(**params)
            break
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if (
                error.get("Code") == "ValidationError"
                and "Instance Profile" in error.get("Message", "")
                and time.monotonic() < deadline
            ):
                time.sleep(2)
                continue
            raise

    def _drop():
        # This is the leak-prone resource in this fixture. An ASG left with capacity RELAUNCHES
        # instances forever, so cleanup drains to zero FIRST, then ForceDeletes, then WAITS for the
        # group to disappear. Only then can the launch-template, instance-profile and
        # security-group teardowns registered earlier (LIFO: they run after this) succeed.
        _swallow(
            lambda: asg.update_auto_scaling_group(
                AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0
            )
        )
        _swallow(
            lambda: asg.delete_auto_scaling_group(
                AutoScalingGroupName=name, ForceDelete=True
            )
        )
        for _ in range(450):
            if not _describe_groups(ctx, name):
                return
            time.sleep(2)
        raise RuntimeError(f"auto scaling group {name} still present after ForceDelete")

    ctx.on_cleanup(_drop)
    return name


def _describe_groups(ctx, name: str) -> list:
    """Paginated: a filtered Describe can still return several pages."""
    groups = []
    for page in (
        ctx.client("autoscaling")
        .get_paginator("describe_auto_scaling_groups")
        .paginate(AutoScalingGroupNames=[name])
    ):
        groups += page["AutoScalingGroups"]
    return groups


def _members(ctx, name: str) -> list[dict]:
    groups = _describe_groups(ctx, name)
    assert groups, f"auto scaling group {name!r} not found"
    return groups[0]["Instances"]


def _get_object(ctx, bucket: str, key: str):
    """The object's body as text, or None while it does not exist yet."""
    try:
        return (
            ctx.client("s3")
            .get_object(Bucket=bucket, Key=key)["Body"]
            .read()
            .decode("utf-8", "replace")
        )
    except ctx.client("s3").exceptions.NoSuchKey:
        return None


def _instance(ctx, instance_id: str) -> dict:
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_instances").paginate(
        InstanceIds=[instance_id]
    ):
        for res in page["Reservations"]:
            for inst in res["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst
    raise AssertionError(f"instance {instance_id!r} not found in DescribeInstances")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
