"""deep-autoscaling-3-asg-notify-test-notification-reaches-only-the-configured-topic."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deep-autoscaling-3-asg-notify-test-notification-reaches-only-the-configured-topic"
GROUP = "notification-delivery"
SERVICES = ["autoscaling", "ec2", "sns", "sqs"]


@tags("axis:negative-delivery", "concern:eventing", "dp:api", "plane:data", "cap:c1", "cap:c5")
def run(ctx) -> None:
    """Configuring one of two live topic->queue pipes delivers a TEST_NOTIFICATION naming the group
    to it alone; configuring the second then delivers to its queue too, and removing the
    configurations one at a time leaves exactly the remaining one listed, then none."""
    estate = _new_estate()
    ctx.on_cleanup(lambda: _dismantle(ctx, estate, raise_on_leak=True))
    try:
        asg = ctx.client("autoscaling")

        lit_topic, lit_queue = _pipe(ctx, estate, "lit")
        dark_topic, dark_queue = _pipe(ctx, estate, "dark")

        # Both pipes are live end to end BEFORE any absence means anything.
        for topic, queue, label in ((lit_topic, lit_queue, "lit"), (dark_topic, dark_queue, "dark")):
            canary = ctx.unique_name(f"sim2real-canary-{label}-")
            _publish_until_delivered(ctx, topic, queue, canary)

        ami = _al2023_ami(ctx)
        _vpc, _azs, subnets = _network(ctx, estate, "t3.micro", want=1)
        lt_name = _launch_template(ctx, estate, ami)
        group = _create_asg(ctx, estate, lt_name, subnets, min_size=0, max_size=1, desired=0)
        group_arn = _group(ctx, group)["AutoScalingGroupARN"]

        # Round-trip 1: configure the lit topic only.
        asg.put_notification_configuration(
            AutoScalingGroupName=group, TopicARN=lit_topic,
            NotificationTypes=["autoscaling:TEST_NOTIFICATION"],
        )
        configs = _configs(ctx, group)
        assert configs == [(lit_topic, "autoscaling:TEST_NOTIFICATION")], (
            f"DescribeNotificationConfigurations must list exactly the lit topic, got {configs!r}"
        )

        first = _await_event(ctx, lit_queue, lit_topic, "autoscaling:TEST_NOTIFICATION",
                             timeout_s=300)
        assert first.get("AutoScalingGroupName") == group, (
            f"the TEST_NOTIFICATION must name group {group!r}, got {first!r}"
        )
        assert first.get("AutoScalingGroupARN") == group_arn, (
            f"the TEST_NOTIFICATION must carry the group ARN {group_arn!r}, got {first!r}"
        )

        # Sustained barrier: the lit side delivered, then drains to empty and stays empty.
        trailing = _drain(ctx, lit_queue, wait_s=20)
        assert all(json.loads(e["Message"]).get("AutoScalingGroupName") == group
                   for e in trailing), (
            f"the lit queue carried a message naming some other group: {trailing!r}"
        )
        # The absence, asserted only now that the lit side delivered and went quiet.
        stray = _drain(ctx, dark_queue, wait_s=20)
        assert stray == [], (
            f"the UNCONFIGURED topic's queue received {len(stray)} message(s) although no "
            f"notification configuration names it: {stray!r}"
        )

        # Round-trip 2: repair the one broken thing; the SAME dark queue must now receive.
        asg.put_notification_configuration(
            AutoScalingGroupName=group, TopicARN=dark_topic,
            NotificationTypes=["autoscaling:TEST_NOTIFICATION"],
        )
        repaired = _await_event(ctx, dark_queue, dark_topic, "autoscaling:TEST_NOTIFICATION",
                                timeout_s=300)
        assert repaired.get("AutoScalingGroupName") == group, (
            f"after configuring the second topic its TEST_NOTIFICATION must name {group!r}, "
            f"got {repaired!r}"
        )
        configs = _configs(ctx, group)
        assert sorted(configs) == sorted([(lit_topic, "autoscaling:TEST_NOTIFICATION"),
                                          (dark_topic, "autoscaling:TEST_NOTIFICATION")]), (
            f"both topics must now be listed, got {configs!r}"
        )

        # Round-trip 3: removing one configuration leaves exactly the other.
        asg.delete_notification_configuration(AutoScalingGroupName=group, TopicARN=lit_topic)
        configs = _configs(ctx, group)
        assert configs == [(dark_topic, "autoscaling:TEST_NOTIFICATION")], (
            f"after deleting the lit configuration only the dark one may remain, got {configs!r}"
        )
        # Round-trip 4: removing the last leaves the group with none.
        asg.delete_notification_configuration(AutoScalingGroupName=group, TopicARN=dark_topic)
        configs = _configs(ctx, group)
        assert configs == [], f"after deleting both configurations none may remain, got {configs!r}"
    finally:
        _dismantle(ctx, estate)


_CIDR_OCTET = 225
_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = {"sim2real": CHECK[:200], "sim2real:managed": "true"}
#: Ceiling for the in-body teardown to see every Auto Scaling group gone before the network
#: under it is deleted. Teardown runs INSIDE the check budget (try/finally in run), because the
#: cleanup chain is bounded at 60 s -- far too short to drain a group with instances.
DISMANTLE_WAIT_S = 900


def _new_estate() -> dict:
    return {"groups": [], "tgs": [], "lts": [], "subnets": [], "vpcs": [],
            "subs": [], "topics": [], "queues": []}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


_ASG_BUSY = ("ScalingActivityInProgress", "ResourceInUse", "ResourceContention")


def _asg_gone(err: dict) -> bool:
    """The group is already deleted: Auto Scaling answers ValidationError '... not found'."""
    return err["Code"] == "ValidationError" and "not found" in err.get("Message", "")


def _codes(*codes: str):
    """A ``gone`` test that matches the operation's documented not-found codes."""
    return lambda err: err["Code"] in codes


def _retry_delete(fn, what: str, *, gone, busy: tuple = ("DependencyViolation", "ResourceInUse"),
                  attempts: int = 150, interval_s: float = 2.0,
                  leaks: list[str] | None = None) -> bool:
    """Run a teardown call, retrying only the in-use refusals ``busy`` while dependents drain.

    True once done or already gone (``gone(err)``). Any other error stops at once: False, appended
    to ``leaks`` when given, and the item stays in the estate for the raising cleanup net.
    """
    from botocore.exceptions import ClientError

    last: Exception | None = None
    for _ in range(attempts):
        try:
            fn()
            return True
        except ClientError as exc:
            err = exc.response["Error"]
            if gone(err):
                return True
            last = exc
            if err["Code"] not in busy:
                break
        time.sleep(interval_s)
    if leaks is not None:
        leaks.append(f"{what} could not be deleted: {last}")
    return False


def _dismantle(ctx, estate: dict, *, raise_on_leak: bool = False) -> None:
    """Tear the whole estate down; idempotent, so the cleanup net may call it again.

    ``raise_on_leak`` (the registered cleanup) raises one RuntimeError naming everything still
    present after every delete was tried; without it (run's finally) leftovers stay for the cleanup net.

    Whatever could not be deleted stays in ``estate``, so the cleanup net retries and reports it.

    Every FAST delete is issued first (groups force-deleted without waiting, SNS/SQS, launch
    templates), so that if an outer bound cuts this off, what remains is the least. Only then
    does it wait for the groups to vanish and delete what they were holding on to.
    """
    leaks: list[str] | None = [] if raise_on_leak else None
    asg = ctx.client("autoscaling")
    groups = list(estate["groups"])
    for name in groups:
        # Resume everything (a suspended Terminate cannot drain), drain to zero, ForceDelete.
        for label, call in (
            ("resume", lambda name=name: asg.resume_processes(AutoScalingGroupName=name)),
            ("drain", lambda name=name: asg.update_auto_scaling_group(
                AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0)),
            ("force-delete", lambda name=name: asg.delete_auto_scaling_group(
                AutoScalingGroupName=name, ForceDelete=True)),
        ):
            _retry_delete(call, f"auto scaling group {name} ({label})", gone=_asg_gone,
                          busy=_ASG_BUSY, leaks=leaks)
    if estate["subs"] or estate["topics"] or estate["queues"]:
        sns = ctx.client("sns")
        sqs = ctx.client("sqs")
        estate["subs"] = [
            arn for arn in estate["subs"]
            if not _retry_delete(lambda arn=arn: sns.unsubscribe(SubscriptionArn=arn),
                                 f"subscription {arn}", gone=_codes("NotFound"), leaks=leaks)
        ]
        estate["topics"] = [
            arn for arn in estate["topics"]
            if not _retry_delete(lambda arn=arn: sns.delete_topic(TopicArn=arn),
                                 f"topic {arn}", gone=_codes("NotFound"), leaks=leaks)
        ]
        estate["queues"] = [
            url for url in estate["queues"]
            if not _retry_delete(lambda url=url: sqs.delete_queue(QueueUrl=url), f"queue {url}",
                                 gone=_codes("AWS.SimpleQueueService.NonExistentQueue",
                                             "QueueDoesNotExist"), leaks=leaks)
        ]
    ec2 = ctx.client("ec2")
    estate["lts"] = [
        lt for lt in estate["lts"]
        if not _retry_delete(lambda lt=lt: ec2.delete_launch_template(LaunchTemplateName=lt),
                             f"launch template {lt}", attempts=8, interval_s=2,
                             gone=_codes("InvalidLaunchTemplateName.NotFoundException"), leaks=leaks)
    ]

    deadline = time.monotonic() + DISMANTLE_WAIT_S
    while groups and time.monotonic() < deadline:
        groups = [g for g in groups if _describe_groups(ctx, g)]
        if groups:
            time.sleep(2)
    if leaks is not None:
        leaks.extend(f"auto scaling group {name} still present after ForceDelete" for name in groups)
    estate["groups"] = groups

    if estate["tgs"]:
        elbv2 = ctx.client("elbv2")
        estate["tgs"] = [
            arn for arn in estate["tgs"]
            if not _retry_delete(lambda arn=arn: elbv2.delete_target_group(TargetGroupArn=arn),
                                 f"target group {arn}",
                                 gone=_codes("TargetGroupNotFound"), leaks=leaks)
        ]
    estate["subnets"] = [
        sn for sn in estate["subnets"]
        if not _retry_delete(lambda sn=sn: ec2.delete_subnet(SubnetId=sn), f"subnet {sn}",
                             gone=_codes("InvalidSubnetID.NotFound"), leaks=leaks)
    ]
    estate["vpcs"] = [
        vpc for vpc in estate["vpcs"]
        if not _retry_delete(lambda vpc=vpc: ec2.delete_vpc(VpcId=vpc), f"vpc {vpc}",
                             gone=_codes("InvalidVpcID.NotFound"), leaks=leaks)
    ]
    if leaks:
        raise RuntimeError("; ".join(leaks))


def _poll(fn, pred, *, timeout_s, interval_s=10, description="condition"):
    """Poll fn() until pred() holds; RAISE with the last observed value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s:.0f}s; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


def _al2023_ami(ctx) -> str:
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    value = ctx.client("ssm").get_parameter(Name=param)["Parameter"]["Value"]
    assert value.startswith("ami-"), f"{param} did not resolve to an AMI: {value!r}"
    return value


def _network(ctx, estate: dict, instance_type: str, want: int):
    """A DEDICATED VPC with `want` subnets, in AZs that really offer instance_type.

    A freshly provisioned account may have no default VPC at all, and borrowing an ambient
    one lets a concurrent run's IP exhaustion masquerade as a scaling failure.
    """
    ec2 = ctx.client("ec2")
    offered = sorted(
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    )
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    }
    azs = [z for z in offered if z in available][:want]
    assert len(azs) == want, (
        f"need {want} available AZs offering {instance_type!r} in {ctx.region}, got {azs!r} "
        f"(offered={offered!r})"
    )
    vpc_id = ec2.create_vpc(
        CidrBlock=f"10.{_CIDR_OCTET}.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    estate["vpcs"].append(vpc_id)
    subnet_ids = []
    for index, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.{_CIDR_OCTET}.{index}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
        )["Subnet"]["SubnetId"]
        estate["subnets"].append(subnet_id)
        subnet_ids.append(subnet_id)
    return vpc_id, azs, subnet_ids


def _launch_template(ctx, estate: dict, ami: str, *, instance_type: str = "t3.micro") -> str:
    """Tag BOTH the instance and its volume AT LAUNCH, so the server-minted ids an ASG
    creates stay attributable to this check and reapable if teardown loses one."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"{_PREFIX}as-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami,
            "InstanceType": instance_type,
            "TagSpecifications": [
                {"ResourceType": "instance", "Tags": _tags_kv()},
                {"ResourceType": "volume", "Tags": _tags_kv()},
            ],
        },
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
    )
    estate["lts"].append(name)
    return name


def _create_asg(ctx, estate: dict, lt_name: str, subnets, *, min_size: int, max_size: int,
                desired: int, **kwargs) -> str:
    asg = ctx.client("autoscaling")
    name = ctx.unique_name(f"{_PREFIX}as-grp-")
    params = {
        "AutoScalingGroupName": name,
        "LaunchTemplate": {"LaunchTemplateName": lt_name, "Version": "$Latest"},
        "MinSize": min_size,
        "MaxSize": max_size,
        "DesiredCapacity": desired,
        "VPCZoneIdentifier": ",".join(subnets),
        "HealthCheckGracePeriod": 0,
        "DefaultCooldown": 0,
        "Tags": [
            {"Key": k, "Value": v, "PropagateAtLaunch": True} for k, v in _MANAGED_TAGS.items()
        ],
    }
    params.update(kwargs)
    asg.create_auto_scaling_group(**params)
    estate["groups"].append(name)
    return name


def _describe_groups(ctx, name: str) -> list:
    """Paginated: a filtered Describe can still return several pages."""
    groups = []
    for page in ctx.client("autoscaling").get_paginator(
        "describe_auto_scaling_groups"
    ).paginate(AutoScalingGroupNames=[name]):
        groups += page["AutoScalingGroups"]
    return groups


def _group(ctx, name: str) -> dict:
    groups = _describe_groups(ctx, name)
    assert groups, f"auto scaling group {name!r} not found"
    return groups[0]


def _ids_in_state(ctx, name: str, *states: str) -> list[str]:
    return sorted(
        i["InstanceId"] for i in _group(ctx, name)["Instances"]
        if i["LifecycleState"] in states
    )


def _activities(ctx, name: str) -> list:
    out = []
    for page in ctx.client("autoscaling").get_paginator(
        "describe_scaling_activities"
    ).paginate(AutoScalingGroupName=name):
        out += page["Activities"]
    return out


def _ec2_state(ctx, instance_id: str) -> str:
    ec2 = ctx.client("ec2")
    for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=[instance_id]):
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                if inst["InstanceId"] == instance_id:
                    return inst["State"]["Name"]
    raise AssertionError(f"instance {instance_id!r} not found in DescribeInstances")


def _pipe(ctx, estate: dict, label: str):
    """An SNS topic with an SQS queue subscribed to it; returns (topic_arn, queue_url)."""
    sns = ctx.client("sns")
    sqs = ctx.client("sqs")
    topic_arn = sns.create_topic(
        Name=ctx.unique_name(f"sim2real-xsvc-asn-{label}-"), Tags=_tags_kv()
    )["TopicArn"]
    estate["topics"].append(topic_arn)
    queue_url = sqs.create_queue(
        QueueName=ctx.unique_name(f"sim2real-xsvc-asq-{label}-"),
        tags=dict(_MANAGED_TAGS),
    )["QueueUrl"]
    estate["queues"].append(queue_url)
    queue_arn = sqs.get_queue_attributes(
        QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sns.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": topic_arn}},
        }],
    }
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)})
    sub_arn = sns.subscribe(
        TopicArn=topic_arn, Protocol="sqs", Endpoint=queue_arn, ReturnSubscriptionArn=True
    )["SubscriptionArn"]
    estate["subs"].append(sub_arn)
    return topic_arn, queue_url


def _drain(ctx, queue_url: str, *, wait_s: int) -> list[dict]:
    """Receive (and delete) everything that arrives within wait_s; returns SNS envelopes."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + wait_s
    while True:
        remaining = int(deadline - time.monotonic())
        if remaining <= 0:
            return out
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10,
                                   WaitTimeSeconds=min(20, max(1, remaining)))
        for m in resp.get("Messages", []):
            out.append(json.loads(m["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])


def _publish_until_delivered(ctx, topic_arn: str, queue_url: str, marker: str) -> None:
    """Prove a topic->queue pipe delivers; retried because the queue policy propagates."""
    sns = ctx.client("sns")
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        sns.publish(TopicArn=topic_arn, Message=marker)
        for env in _drain(ctx, queue_url, wait_s=20):
            if env.get("Message") == marker:
                # Swallow any duplicate retries of the canary so the queue starts clean.
                _drain(ctx, queue_url, wait_s=5)
                return
    raise AssertionError(f"canary {marker!r} never traversed {topic_arn} -> {queue_url}")


def _await_event(ctx, queue_url: str, topic_arn: str, event: str, *, timeout_s: int) -> dict:
    """Wait for an Auto Scaling notification of type `event`; returns its parsed body."""
    seen = []
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for env in _drain(ctx, queue_url, wait_s=20):
            assert env.get("TopicArn") == topic_arn, (
                f"a message on {queue_url} came from {env.get('TopicArn')!r}, not {topic_arn!r}"
            )
            body = json.loads(env["Message"])
            seen.append(body.get("Event"))
            if body.get("Event") == event:
                return body
    raise AssertionError(f"no {event!r} arrived on {queue_url} within {timeout_s}s; saw {seen!r}")


def _configs(ctx, group: str) -> list[tuple[str, str]]:
    out = []
    for page in ctx.client("autoscaling").get_paginator(
        "describe_notification_configurations"
    ).paginate(AutoScalingGroupNames=[group]):
        out += [(c["TopicARN"], c["NotificationType"]) for c in page["NotificationConfigurations"]]
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
