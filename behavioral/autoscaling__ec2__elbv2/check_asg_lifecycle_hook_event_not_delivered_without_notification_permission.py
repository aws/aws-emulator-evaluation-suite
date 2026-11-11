"""asg-lifecycle-hook-event-not-delivered-without-notification-permission."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "asg-lifecycle-hook-event-not-delivered-without-notification-permission"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ec2", "elbv2"]

_ASG_NOTIFICATION_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AutoScalingNotificationAccessRole"


@tags("axis:rejection", "cap:c7", "concern:eventing", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """PutLifecycleHook with a role that cannot publish to the SQS target fails with ValidationError
    and its exact message; with a role that can, the hook's TEST_NOTIFICATION reaches the queue."""
    queue_url, queue_arn = _create_sqs_queue(ctx)
    asg_name = ctx.unique_name("sim2real-asg-")
    lt_id = _create_dummy_launch_template(ctx)
    az = _first_availability_zone(ctx)

    asg = ctx.client("autoscaling")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        Tags=[
            {
                "ResourceId": asg_name,
                "ResourceType": "auto-scaling-group",
                "Key": "Name",
                "Value": asg_name,
                "PropagateAtLaunch": False,
            }
        ],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: asg.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )

    no_perm_role_arn = _create_asg_notification_role(ctx, attach_policy=False)
    has_perm_role_arn = _create_asg_notification_role(ctx, attach_policy=True)

    # PutLifecycleHook publishes a TEST_NOTIFICATION synchronously, so a role that cannot
    # publish to the queue is refused with ValidationError and no hook is created.
    neg_hook = ctx.unique_name("sim2real-hook-neg-")
    try:
        asg.put_lifecycle_hook(
            LifecycleHookName=neg_hook,
            AutoScalingGroupName=asg_name,
            LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
            RoleARN=no_perm_role_arn,
            NotificationTargetARN=queue_arn,
            HeartbeatTimeout=60,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        msg = exc.response.get("Error", {}).get("Message", "")
        expected_msg = (
            f"Unable to publish test message to notification target {queue_arn} using IAM role "
            f"{no_perm_role_arn}. Please check your target and role configuration and try to put "
            f"lifecycle hook again."
        )
        assert code == "ValidationError", f"expected a publish-permission ValidationError, got {code}: {msg}"
        assert msg == expected_msg, f"ValidationError message {msg!r}, expected {expected_msg!r}"
    else:
        raise AssertionError(
            f"PutLifecycleHook {neg_hook!r} with a role that cannot publish to {queue_arn} was "
            f"accepted; AWS refuses it synchronously with ValidationError"
        )

    # Positive control: same ASG, same queue, a role that CAN publish -> delivered.
    pos_hook = ctx.unique_name("sim2real-hook-pos-")
    deadline = time.monotonic() + 60.0
    last_err: Exception | None = None
    created = False
    while time.monotonic() < deadline:
        try:
            asg.put_lifecycle_hook(
                LifecycleHookName=pos_hook,
                AutoScalingGroupName=asg_name,
                LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
                RoleARN=has_perm_role_arn,
                NotificationTargetARN=queue_arn,
                HeartbeatTimeout=60,
            )
            created = True
            break
        except ClientError as exc:  # role/trust not yet propagated through IAM
            last_err = exc
            time.sleep(5)
    if not created:
        raise AssertionError(f"PutLifecycleHook with a permitted role kept failing: {last_err}")

    # The TEST_NOTIFICATION payload does not echo back the hook name, only the
    # group -- match on group + event type (the negative case above was refused
    # synchronously, so the hook that publishes here is the permitted one).
    event = _poll_sqs_for_message(
        ctx,
        queue_url,
        lambda body: body.get("AutoScalingGroupName") == asg_name
        and body.get("Event") == "autoscaling:TEST_NOTIFICATION",
        timeout_s=90.0,
    )
    assert event.get("Event") == "autoscaling:TEST_NOTIFICATION", (
        f"expected Event=autoscaling:TEST_NOTIFICATION, got {event.get('Event')!r} in {event!r}"
    )
    assert event.get("AutoScalingGroupName") == asg_name, (
        f"expected AutoScalingGroupName={asg_name!r}, got {event.get('AutoScalingGroupName')!r}"
    )


def _create_sqs_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-q-")
    url = sqs.create_queue(QueueName=name)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    sqs.tag_queue(QueueUrl=url, Tags={"Name": name})
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return url, arn


def _first_availability_zone(ctx) -> str:
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}])[
        "AvailabilityZones"
    ]
    return azs[0]["ZoneName"]


def _create_dummy_launch_template(ctx) -> str:
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    ami_id = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    name = ctx.unique_name("sim2real-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg_notification_role(ctx, attach_policy: bool) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-asg-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "autoscaling.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "Name", "Value": role_name}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if attach_policy:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=_ASG_NOTIFICATION_POLICY_ARN)
        ctx.on_cleanup(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_ASG_NOTIFICATION_POLICY_ARN)
        )
    return role_arn


def _poll_sqs_for_message(ctx, queue_url: str, predicate, timeout_s: float = 180.0) -> dict:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            if isinstance(body, dict) and predicate(body):
                return body
    raise AssertionError(f"expected message not received on {queue_url} within {timeout_s}s")


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
