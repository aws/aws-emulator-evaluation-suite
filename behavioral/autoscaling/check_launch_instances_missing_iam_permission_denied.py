"""launch-instances-missing-iam-permission-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "launch-instances-missing-iam-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateAutoScalingGroup by a caller with no IAM permissions is rejected with an access-denied
    error and creates no group, while the same call with permitted credentials succeeds."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    asgc = ctx.client("autoscaling")

    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-norole-")
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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    session_name = ctx.unique_name("sim2real-behav-sess-")
    creds = _assume_role_with_retry(sts, role_arn, session_name, timeout_s=60)
    assert creds is not None, "could not assume the freshly created (permission-less) role in time"

    restricted_asgc = ctx.client(
        "autoscaling",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    denied_group_name = ctx.unique_name("sim2real-behav-denied-asg-")
    lt_id = _create_launch_template(ctx)
    code, message = _error(
        lambda: restricted_asgc.create_auto_scaling_group(
            AutoScalingGroupName=denied_group_name,
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            AvailabilityZones=[_first_az(ctx)],
            LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
            VPCZoneIdentifier=_network_zone_subnets(ctx, [_first_az(ctx)]),
        )
    )
    assert code == "AccessDenied", f"expected AccessDenied, got {code}"
    region = asgc.meta.region_name
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/{session_name} "
        "is not authorized to perform: autoscaling:CreateAutoScalingGroup on resource: "
        f"arn:aws:autoscaling:{region}:{account_id}:autoScalingGroup:*:"
        f"autoScalingGroupName/{denied_group_name} "
        "because no identity-based policy allows the autoscaling:CreateAutoScalingGroup action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # (b) effect absent: the group was never created.
    groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[denied_group_name])["AutoScalingGroups"]
    assert groups == [], f"group should not exist after a denied create, found: {groups}"

    # (c) positive control: the same call, with real credentials, succeeds.
    control_group_name = ctx.unique_name("sim2real-behav-control-asg-")
    asgc.create_auto_scaling_group(
        AutoScalingGroupName=control_group_name,
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[_first_az(ctx)],
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [_first_az(ctx)]),
    )
    ctx.on_cleanup(lambda: asgc.delete_auto_scaling_group(AutoScalingGroupName=control_group_name, ForceDelete=True))
    groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[control_group_name])["AutoScalingGroups"]
    assert len(groups) == 1, "positive control create did not take effect"


def _create_launch_template(ctx) -> str:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami_id = ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"][
        "Value"
    ]
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )["LaunchTemplate"]
    lt_id = lt["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises, so
    accepting a call AWS denies is not reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected AccessDenied, but the call SUCCEEDED and returned {result!r}")


def _first_az(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
        "AvailabilityZones"
    ]
    return zones[0]["ZoneName"]


def _assume_role_with_retry(sts_client, role_arn: str, session_name: str, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)["Credentials"]
        except ClientError as e:
            last_exc = e
            time.sleep(3)
    if last_exc is not None:
        return None
    return None


def _network_zone_subnets(ctx, zones) -> str:
    """The shared network's subnets in `zones`, comma-separated for VPCZoneIdentifier."""
    by_zone = ctx.network().subnets
    missing = [z for z in zones if z not in by_zone]
    if missing:
        raise AssertionError(f"the run's shared network has no subnet in {missing}")
    return ",".join(by_zone[z] for z in zones)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
