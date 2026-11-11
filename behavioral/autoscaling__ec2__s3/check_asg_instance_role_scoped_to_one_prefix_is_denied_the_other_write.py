"""asg-instance-role-scoped-to-one-prefix-is-denied-the-other-write."""

from __future__ import annotations

import base64
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asg-instance-role-scoped-to-one-prefix-is-denied-the-other-write"
GROUP = "overly-permissive"
SERVICES = ["autoscaling", "ec2", "s3"]

_ALLOWED = "allowed"
_DENIED = "denied"


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
    "cap:c5",
)
def run(ctx) -> None:
    """An ASG instance whose role allows PutObject only on bucket/allowed/* gets AccessDenied
    writing bucket/denied/id with its profile credentials; the permitted write from the same
    instance is the barrier that makes the forbidden object's absence evidence."""
    s3 = ctx.client("s3")
    bucket = _bucket(ctx)
    _role, profile = _instance_profile(ctx, bucket, key_prefix=f"{_ALLOWED}/*")
    _vpc, subnets = _usable_subnets(ctx, "t3.micro", want=2)
    sg_id = _egress_only_sg(ctx, _vpc)

    # The forbidden write goes FIRST and the permitted marker LAST, so seeing the marker proves the
    # forbidden attempt has already been made and its outcome already uploaded. The instance reports
    # the exact error code it got through the prefix it IS allowed to write.
    user_data = (
        "#!/bin/bash\n"
        "set -x\n"
        'TOKEN=$(curl -sS -X PUT "http://169.254.169.254/latest/api/token" '
        '-H "X-aws-ec2-metadata-token-ttl-seconds: 300")\n'
        'IID=$(curl -sS -H "X-aws-ec2-metadata-token: $TOKEN" '
        "http://169.254.169.254/latest/meta-data/instance-id)\n"
        "printf '%s' \"$IID\" > /tmp/iid\n"
        f"aws s3api put-object --bucket {bucket} --key {_DENIED}/id --body /tmp/iid "
        f"--region {ctx.region} > /tmp/denied.out 2> /tmp/denied.err\n"
        "printf '%s' \"$?\" > /tmp/denied.rc\n"
        "grep -o 'An error occurred ([A-Za-z]*)' /tmp/denied.err | head -1 "
        "| sed 's/^.*(\\(.*\\))$/\\1/' > /tmp/denied.code\n"
        f"aws s3api put-object --bucket {bucket} --key {_ALLOWED}/denied-rc "
        f"--body /tmp/denied.rc --region {ctx.region}\n"
        f"aws s3api put-object --bucket {bucket} --key {_ALLOWED}/denied-code "
        f"--body /tmp/denied.code --region {ctx.region}\n"
        f"aws s3api put-object --bucket {bucket} --key {_ALLOWED}/id --body /tmp/iid "
        f"--region {ctx.region}\n"
    )
    lt_name = _launch_template(
        ctx, _al2023_ami(ctx), user_data=user_data, sg_ids=[sg_id], profile=profile
    )
    name = _create_asg(ctx, lt_name, subnets, min_size=1, max_size=1, desired=1)

    asg_instance_id = _poll(
        ctx,
        lambda: [
            i["InstanceId"]
            for i in _members(ctx, name)
            if i["LifecycleState"] == "InService"
        ],
        lambda ids: len(ids) == 1,
        timeout_s=1200,
        description="the ASG reported one InService instance",
    )[0]

    # --- The barrier: the PERMITTED write arriving proves boot, credentials and S3 reachability.
    allowed_body = _poll(
        ctx,
        lambda: _get_object(ctx, bucket, f"{_ALLOWED}/id"),
        lambda b: b is not None,
        timeout_s=900,
        description=f"the instance wrote the permitted s3://{bucket}/{_ALLOWED}/id",
    )
    assert allowed_body is not None, (
        f"the instance never wrote the permitted object, so nothing below is evidence: no "
        f"s3://{bucket}/{_ALLOWED}/id"
    )
    assert allowed_body.strip() == asg_instance_id, (
        f"the permitted object names a different instance than the ASG reports: "
        f"{allowed_body.strip()!r} != {asg_instance_id!r}"
    )

    # --- The exact code AWS handed the instance for the write outside its policy's scope.
    denied_code = _poll(
        ctx,
        lambda: _get_object(ctx, bucket, f"{_ALLOWED}/denied-code"),
        lambda b: b is not None,
        timeout_s=300,
        description="the instance reported the error code its forbidden write got",
    )
    assert denied_code.strip() == "AccessDenied", (
        f"the write outside the role's Resource scope was not denied with AccessDenied: the "
        f"instance recorded {denied_code.strip()!r}"
    )
    denied_rc = _get_object(ctx, bucket, f"{_ALLOWED}/denied-rc")
    assert denied_rc is not None and denied_rc.strip() != "0", (
        f"the forbidden write reported success on the instance: exit status {denied_rc!r}"
    )

    # --- The effect that must be ABSENT: nothing under the prefix the policy does not name.
    code = _error_code(lambda: s3.head_object(Bucket=bucket, Key=f"{_DENIED}/id"))
    assert code == "404", (
        f"the object the instance was denied permission to write EXISTS: HeadObject on "
        f"{_DENIED}/id returned {code!r}"
    )
    keys = _list_keys(ctx, bucket)
    assert not [k for k in keys if k.startswith(f"{_DENIED}/")], (
        f"objects exist under the prefix the instance role does not name: {sorted(keys)!r}"
    )


# ===== self-contained helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = {"sim2real": "as-deny", "sim2real:managed": "true"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    try:
        fn()
    except Exception:  # noqa: BLE001 - best-effort teardown
        pass


def _poll(ctx, fn, pred, *, timeout_s, interval_s=2, description="condition"):
    """Poll fn() until pred() holds; raise with the last observed value on timeout."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not met within {timeout_s}s; last={last!r}"
            )
        time.sleep(interval_s)
        last = fn()
    return last


def _error_code(fn) -> str:
    """The exact AWS error code fn() raises.

    Raises when the call SUCCEEDS instead of returning a falsy sentinel: here a success means the
    object the instance was denied permission to write actually exists, which is the strongest
    signal in this check and must not be disguised as a code mismatch.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError("the call was expected to be rejected but it succeeded")


def _al2023_ami(ctx) -> str:
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    value = ctx.client("ssm").get_parameter(Name=param)["Parameter"]["Value"]
    assert value.startswith("ami-"), f"{param} did not resolve to an AMI: {value!r}"
    return value


def _usable_subnets(ctx, instance_type: str, want: int = 1):
    """Public default-VPC subnets in AZs that ACTUALLY OFFER instance_type.

    The shared network is used deliberately: its subnets already have an internet-gateway route and
    auto-assign a public IP, so the instance reaches S3 with no NAT gateway and no EIP left behind.
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
        Description="sim2real asg instance role scope, egress only",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _tags_kv()}],
    )["GroupId"]

    def _drop():
        for _ in range(24):
            try:
                ec2.delete_security_group(GroupId=gid)
                return
            except Exception:  # noqa: BLE001 - ENI still detaching
                time.sleep(10)
        raise RuntimeError(f"security group {gid} could not be deleted")

    ctx.on_cleanup(_drop)
    return gid


def _bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(_XSVC_PREFIX + "deny-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's own default and rejects an explicit LocationConstraint --
        # not a pin to any particular target region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _drop():
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
    """(role, instance profile) letting the instance PutObject ONLY under bucket/<key_prefix>.

    IAM exposes no API that reports a policy has become effective, so the only correct bound on
    propagation is a retry at FIRST USE -- the ASG's own launch retry loop plus the bounded S3 poll
    in run() absorb it. No fixed pre-sleep here: it would race the very propagation it exists for.
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
        Description="sim2real asg instance role scope",
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
        ctx,
        lambda: iam.get_instance_profile(InstanceProfileName=profile)[
            "InstanceProfile"
        ]["Roles"],
        lambda roles: [r["RoleName"] for r in roles] == [role],
        timeout_s=120,
        description=f"instance profile {profile} reports role {role}",
    )
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
        for _ in range(12):
            try:
                ec2.delete_launch_template(LaunchTemplateName=name)
                return
            except Exception:  # noqa: BLE001 - still referenced by a deleting ASG
                time.sleep(10)
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
    # Retry only the transient IAM-propagation race (CreateAutoScalingGroup validates the launch
    # template's instance profile synchronously, and can reject it as not-yet-visible right after
    # create). A genuine bad profile name is not in this set, so it surfaces as a real failure.
    left = ctx.time_left()
    deadline = time.monotonic() + (90 if left is None else min(90, left))
    while True:
        try:
            asg.create_auto_scaling_group(**params)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = str(exc)
            if code == "ValidationError" and "Invalid IAM Instance Profile" in msg:
                if time.monotonic() >= deadline:
                    raise
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
        for _ in range(90):
            if not _describe_groups(ctx, name):
                return
            time.sleep(10)
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


def _head_code(ctx, bucket: str, key: str) -> str:
    """The HeadObject error code for key, or "200" if the object exists."""
    try:
        ctx.client("s3").head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return "200"


def _list_keys(ctx, bucket: str) -> list[str]:
    """Every key in the bucket, paginated -- the membership assertion must see all of them."""
    keys: list[str] = []
    for page in (
        ctx.client("s3").get_paginator("list_objects_v2").paginate(Bucket=bucket)
    ):
        keys += [o["Key"] for o in page.get("Contents", [])]
    return keys


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
