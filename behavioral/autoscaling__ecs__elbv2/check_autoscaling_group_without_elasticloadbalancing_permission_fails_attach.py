"""autoscaling-group-without-elasticloadbalancing-permission-fails-attach."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "autoscaling-group-without-elasticloadbalancing-permission-fails-attach"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ecs", "elbv2"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A caller denied elasticloadbalancing:RegisterTargets still attaches a target group to an ASG.

    Auto Scaling registers the instance with its own service-linked role; a direct RegisterTargets
    call under the same identity is refused with AccessDenied as the control.
    """
    vpc_id, subnet_ids = _get_default_vpc_and_subnets(ctx)
    ami_id = _latest_al2023_ami(ctx)
    sg_id = _create_web_sg(ctx, vpc_id)
    lt_id = _create_launch_template(ctx, ami_id, sg_id, user_data_script=_HTTPD_USER_DATA)
    tg_arn = _create_target_group(ctx, vpc_id)
    asg_name = _create_asg(
        ctx, lt_id, subnet_ids, desired_capacity=1, min_size=1, max_size=1,
        target_group_arns=None, health_check_type="EC2", health_check_grace_period=90,
    )
    instance_ids = _wait_for_asg_instance_ids(ctx, asg_name, count=1, timeout_s=300)

    # DescribeTags is denied only as a side-effect-free probe: IAM policy changes are eventually
    # consistent, so poll it until the Deny is in effect before trusting the calls below.
    role_arn = _create_deny_role(
        ctx,
        deny_actions=[
            "elasticloadbalancing:RegisterTargets",
            "autoscaling:DescribeTags",
        ],
    )
    restricted_asg = _assume_role_client(ctx, "autoscaling", role_arn, timeout_s=90)
    _wait_for_denied(lambda: restricted_asg.describe_tags(), timeout_s=90)

    # Control: a direct elbv2 call, not routed through Auto Scaling's role, is denied.
    restricted_elbv2 = _assume_role_client(ctx, "elbv2", role_arn, timeout_s=90)
    direct_code, direct_message = _error(
        lambda: restricted_elbv2.register_targets(
            TargetGroupArn=tg_arn, Targets=[{"Id": instance_ids[0], "Port": 80}]
        )
    )
    assert direct_code == "AccessDenied", (
        f"expected the direct elbv2.RegisterTargets call to be denied on this identity "
        f"(control for the deny being active), got {direct_code!r}"
    )
    account_id = role_arn.split(":")[4]
    role_name = role_arn.rsplit("/", 1)[1]
    action = "elasticloadbalancing:RegisterTargets"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{_SESSION_NAME} "
        f"is not authorized to perform: {action} on resource: {tg_arn} with an explicit deny in "
        f"an identity-based policy"
    )
    assert direct_message == expected_message, (
        f"AccessDenied message {direct_message!r}, expected {expected_message!r}"
    )

    restricted_asg.attach_load_balancer_target_groups(AutoScalingGroupName=asg_name, TargetGroupARNs=[tg_arn])

    descs = _wait_for_target_ids(ctx, tg_arn, instance_ids, timeout_s=300)
    seen_ids = {d["Target"]["Id"] for d in descs}
    assert seen_ids == set(instance_ids), (
        f"expected {set(instance_ids)} registered on {tg_arn} despite the caller's elb "
        f"deny, saw {seen_ids}"
    )


_HTTPD_USER_DATA = "#!/bin/bash\nyum install -y httpd\nsystemctl enable httpd\nsystemctl start httpd\n"


_SESSION_NAME = "sim2real-sess"


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; a SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be denied, but it SUCCEEDED and returned {result!r}")


def _get_default_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region for ASG test instances")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets available for ASG test instances")
    return vpc_id, [s["SubnetId"] for s in subnets]


def _latest_al2023_ami(ctx):
    ssm = ctx.client("ssm")
    name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=name)["Parameter"]["Value"]


def _create_web_sg(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-asgtg-sg-")
    sg_id = ec2.create_security_group(
        GroupName=name,
        Description="sim2real behavioral test sg",
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}],
    )["GroupId"]

    def _cleanup():
        deadline = time.monotonic() + 180
        while True:
            try:
                ec2.delete_security_group(GroupId=sg_id)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidGroup.NotFound":
                    return
                if code != "DependencyViolation" or time.monotonic() >= deadline:
                    raise
                time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return sg_id


def _create_launch_template(ctx, ami_id, sg_id, user_data_script=None):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-asgtg-lt-")
    lt_data = {"ImageId": ami_id, "InstanceType": "t3.micro", "SecurityGroupIds": [sg_id]}
    if user_data_script:
        import base64

        lt_data["UserData"] = base64.b64encode(user_data_script.encode()).decode()
    lt_id = ec2.create_launch_template(LaunchTemplateName=name, LaunchTemplateData=lt_data)["LaunchTemplate"][
        "LaunchTemplateId"
    ]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_target_group(ctx, vpc_id, port=80):
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-asgtg-tg-")
    tg = elbv2.create_target_group(
        Name=name,
        Protocol="HTTP",
        Port=port,
        VpcId=vpc_id,
        TargetType="instance",
        HealthCheckProtocol="HTTP",
        HealthCheckPort="traffic-port",
        HealthCheckPath="/",
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
        HealthCheckIntervalSeconds=10,
    )["TargetGroups"][0]
    tg_arn = tg["TargetGroupArn"]
    ctx.on_cleanup(lambda: _delete_target_group_when_free(elbv2, tg_arn))
    return tg_arn


def _create_asg(
    ctx, lt_id, subnet_ids, *, min_size=1, max_size=2, desired_capacity=1,
    target_group_arns=None, health_check_type="EC2", health_check_grace_period=60,
):
    asg = ctx.client("autoscaling")
    name = ctx.unique_name("sim2real-asgtg-asg-")
    params = dict(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired_capacity,
        VPCZoneIdentifier=",".join(subnet_ids),
        HealthCheckType=health_check_type,
        HealthCheckGracePeriod=health_check_grace_period,
    )
    if target_group_arns:
        params["TargetGroupARNs"] = target_group_arns
    asg.create_auto_scaling_group(**params)

    def _cleanup():
        busy = ("ScalingActivityInProgress", "ResourceContention", "ResourceInUse")
        try:
            asg.update_auto_scaling_group(AutoScalingGroupName=name, MinSize=0, DesiredCapacity=0)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                return
            if err["Code"] not in busy:
                raise
        # ForceDelete terminates the instances itself; retry while a scaling activity holds the group,
        # then poll until the group is gone. One 960 s deadline covers both.
        deadline = time.monotonic() + 960
        while True:
            try:
                asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
                break
            except ClientError as exc:
                err = exc.response["Error"]
                if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                    return
                if err["Code"] not in busy or time.monotonic() >= deadline:
                    raise
                time.sleep(2)
        while time.monotonic() < deadline:
            resp = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])
            if not resp["AutoScalingGroups"]:
                return
            time.sleep(2)
        raise AssertionError(f"ASG {name} still listed at its 960 s teardown deadline")

    ctx.on_cleanup(_cleanup)
    return name


def _wait_for_asg_instance_ids(ctx, asg_name, count, timeout_s=300.0):
    asg = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    last = []
    while time.monotonic() < deadline:
        resp = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
        if resp:
            last = resp[0]["Instances"]
            if len(last) >= count:
                return [i["InstanceId"] for i in last]
        time.sleep(2)
    raise AssertionError(f"ASG {asg_name} never reached {count} instances (last={last})")


def _wait_for_target_ids(ctx, tg_arn, expected_ids, timeout_s=300.0):
    elbv2 = ctx.client("elbv2")
    deadline = time.monotonic() + timeout_s
    seen: set[str] = set()
    descs = []
    while time.monotonic() < deadline:
        descs = elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
        seen = {d["Target"]["Id"] for d in descs}
        if set(expected_ids).issubset(seen):
            return descs
        time.sleep(2)
    raise AssertionError(f"target group {tg_arn} never registered {expected_ids}; saw {seen}")


def _wait_for_denied(fn, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            fn()
            last = "success"
        except ClientError as err:
            last = err.response["Error"]["Code"]
            if last == "AccessDenied":
                return
        time.sleep(5)
    raise AssertionError(f"deny policy never took effect on propagation probe; last code={last!r}")


def _create_deny_role(ctx, deny_actions):
    """Create a role assumable by our own account root, allowed broadly but with
    an explicit Deny on `deny_actions` (identity-based explicit Deny always wins)."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-asgtg-deny-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = ctx.unique_name("sim2real-asgtg-deny-policy-")
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["autoscaling:*", "elasticloadbalancing:Describe*"], "Resource": "*"},
            {"Effect": "Deny", "Action": deny_actions, "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _assume_role_client(ctx, service, role_arn, timeout_s=90.0):
    """Assume role_arn (retrying while the trust relationship propagates) and
    return a ctx client for `service` signing as that role against the same target."""
    sts = ctx.client("sts")
    deadline = time.monotonic() + timeout_s
    creds = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
            break
        except ClientError as err:
            last_err = err
            time.sleep(5)
    if creds is None:
        raise AssertionError(f"could not assume role {role_arn} in {timeout_s}s: {last_err}")

    return ctx.client(service, creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })



def _delete_target_group_when_free(elbv2, arn, timeout_s=600.0, interval_s=10.0):
    """Delete a target group once no listener or deleting load balancer still uses it (ResourceInUse)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            elbv2.delete_target_group(TargetGroupArn=arn)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "TargetGroupNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
