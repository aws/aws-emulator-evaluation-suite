"""deep-autoscaling-3-asg-suspend-add-to-load-balancer-withholds-registration."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "deep-autoscaling-3-asg-suspend-add-to-load-balancer-withholds-registration"
GROUP = "process-suspension"
SERVICES = ["autoscaling", "ec2", "elbv2"]


@tags("axis:negative-delivery", "cap:c4", "concern:data-plane",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """With AddToLoadBalancer suspended, an ASG instance goes InService but stays unregistered from
    the shared target group while a control registers; after resume new instances register and the
    instance launched during the suspension is not back-filled.

    Reference: https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-suspend-resume-processes.html
    """
    estate = _new_estate()
    ctx.on_cleanup(lambda: _dismantle(ctx, estate, raise_on_leak=True))
    try:
        asg = ctx.client("autoscaling")
        elbv2 = ctx.client("elbv2")

        ami = _al2023_ami(ctx)
        vpc_id, _azs, subnets = _network(ctx, estate, "t3.micro", want=1)
        tg_arn = _create_target_group(ctx, estate, vpc_id)
        lt_name = _launch_template(ctx, estate, ami)
        control = _create_asg(ctx, estate, lt_name, subnets, min_size=0, max_size=2, desired=0,
                              TargetGroupARNs=[tg_arn])
        subject = _create_asg(ctx, estate, lt_name, subnets, min_size=0, max_size=2, desired=0,
                              TargetGroupARNs=[tg_arn])

        for name in (control, subject):
            attached = [t["LoadBalancerTargetGroupARN"]
                        for t in asg.describe_load_balancer_target_groups(
                            AutoScalingGroupName=name)["LoadBalancerTargetGroups"]]
            assert attached == [tg_arn], (
                f"setup: {name} must have exactly the shared target group attached, got {attached!r}"
            )
        assert _registered(elbv2, tg_arn) == set(), (
            f"setup: the fresh target group must have no targets, got {_registered(elbv2, tg_arn)!r}"
        )

        # Break exactly one thing, on the subject only.
        asg.suspend_processes(AutoScalingGroupName=subject, ScalingProcesses=["AddToLoadBalancer"])
        suspended = {p["ProcessName"] for p in _group(ctx, subject)["SuspendedProcesses"]}
        assert suspended == {"AddToLoadBalancer"}, (
            f"the subject must have exactly AddToLoadBalancer suspended, got {sorted(suspended)!r}"
        )
        control_suspended = _group(ctx, control)["SuspendedProcesses"]
        assert not control_suspended, (
            f"the control group must have nothing suspended, got {control_suspended!r}"
        )

        # One fan-out, same instant, so no propagation delta exists between the two groups.
        t0 = time.monotonic()
        for name in (control, subject):
            asg.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1)

        # The barrier: the control's instance is launched AND registered.
        control_ids = _poll(
            lambda: _ids_in_state(ctx, control, "InService"),
            lambda ids: len(ids) == 1,
            timeout_s=_budget_s(ctx, 900), interval_s=1, ctx=ctx,
            description="the control group reached 1 InService instance",
        )
        control_id = control_ids[0]
        _poll(
            lambda: _registered(elbv2, tg_arn),
            lambda ids: control_id in ids,
            timeout_s=_budget_s(ctx, 600), interval_s=1, ctx=ctx,
            description=f"the control instance {control_id} appeared in the target group",
        )

        # The subject launches and goes InService in the ASG's own view -- the work happened.
        subject_ids = _poll(
            lambda: _ids_in_state(ctx, subject, "InService"),
            lambda ids: len(ids) == 1,
            timeout_s=_budget_s(ctx, 900), interval_s=1, ctx=ctx,
            description="the subject group reached 1 InService instance",
        )
        subject_id = subject_ids[0]
        assert subject_id != control_id, (
            f"the two groups must hold different instances, both report {subject_id!r}"
        )
        assert _ec2_state(ctx, subject_id) == "running", (
            f"the subject's instance {subject_id} must be running in EC2, got "
            f"{_ec2_state(ctx, subject_id)!r}"
        )

        # The withholding: absent for a fixed hold past InService, observed continuously while
        # the control's registration stays put.
        hold_until = time.monotonic() + _HOLD_S
        samples = 0
        while True:
            registered = _registered(elbv2, tg_arn)
            assert subject_id not in registered, (
                f"the subject's instance {subject_id} was registered with the target group although "
                f"AddToLoadBalancer is suspended ({time.monotonic() - t0:.0f}s after scale-out); "
                f"registered={sorted(registered)!r}"
            )
            assert registered == {control_id}, (
                f"the target group must hold exactly the control's instance during the hold, got "
                f"{sorted(registered)!r} (control={control_id!r})"
            )
            samples += 1
            if time.monotonic() >= hold_until and samples >= 3:
                break
            time.sleep(2)
        assert samples >= 3, f"the absence must be sampled at least 3 times, got {samples}"

        # Second observable: asked about by id, the target group reports it as not registered.
        by_id = _health_of(elbv2, tg_arn, subject_id)
        assert by_id.get("Reason") == "Target.NotRegistered", (
            f"DescribeTargetHealth for the withheld instance {subject_id} must say "
            f"Target.NotRegistered, got {by_id!r}"
        )
        still_in_service = _ids_in_state(ctx, subject, "InService")
        assert still_in_service == [subject_id], (
            f"the subject's instance must still be InService in the ASG's view, got "
            f"{still_in_service!r}"
        )

        # Repair the one broken thing.
        asg.resume_processes(AutoScalingGroupName=subject, ScalingProcesses=["AddToLoadBalancer"])
        remaining = _group(ctx, subject)["SuspendedProcesses"]
        assert not remaining, f"after the resume nothing may stay suspended, got {remaining!r}"

        # The resumed process registers what it launches from now on: scale the subject out by
        # one, and that new instance's registration is the post-resume barrier.
        asg.set_desired_capacity(AutoScalingGroupName=subject, DesiredCapacity=2)
        new_ids = _poll(
            lambda: [i for i in _ids_in_state(ctx, subject, "Pending", "InService")
                     if i != subject_id],
            lambda ids: len(ids) == 1,
            timeout_s=_budget_s(ctx, 900), interval_s=1, ctx=ctx,
            description="the resumed subject launched a second instance",
        )
        new_id = new_ids[0]
        _poll(
            lambda: _registered(elbv2, tg_arn),
            lambda ids: new_id in ids,
            timeout_s=_budget_s(ctx, 600), interval_s=1, ctx=ctx,
            description=f"the post-resume instance {new_id} appeared in the target group",
        )

        # The instance launched during the suspension is not back-filled (documented); held for
        # a fixed window after the post-resume registration, sampled continuously.
        hold_until = time.monotonic() + _HOLD_S
        samples = 0
        while True:
            registered = _registered(elbv2, tg_arn)
            assert registered == {control_id, new_id}, (
                f"after the resume the target group must hold exactly the control's and the "
                f"post-resume instance {sorted({control_id, new_id})!r}; got {sorted(registered)!r} "
                f"(withheld instance {subject_id} back-filled={subject_id in registered})"
            )
            samples += 1
            if time.monotonic() >= hold_until and samples >= 3:
                break
            time.sleep(2)
        assert samples >= 3, f"the post-resume absence must be sampled 3+ times, got {samples}"
        after = _health_of(elbv2, tg_arn, subject_id)
        assert after.get("Reason") == "Target.NotRegistered", (
            f"the instance launched during the suspension must still be Target.NotRegistered "
            f"after the resume, got {after!r}"
        )
        in_service = _ids_in_state(ctx, subject, "InService", "Pending")
        assert sorted(in_service) == sorted([subject_id, new_id]), (
            f"the subject must hold both its instances, got {in_service!r}"
        )
    finally:
        _dismantle(ctx, estate, wait_s=_budget_s(ctx, DISMANTLE_WAIT_S))


_CIDR_OCTET = 223
_PREFIX = "sim2real-xsvc-"
_MANAGED_TAGS = {"sim2real": CHECK[:200], "sim2real:managed": "true"}
#: Ceiling for every Auto Scaling group to vanish before its network is deleted; teardown runs in
#: run()'s finally because the bounded cleanup chain is too short to drain a group with instances.
DISMANTLE_WAIT_S = 900
#: Fixed absence hold, sampled every 2 s (at least 3 samples).
_HOLD_S = 6


def _new_estate() -> dict:
    return {"groups": [], "tgs": [], "lts": [], "subnets": [], "vpcs": [],
            "subs": [], "topics": [], "queues": []}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


_ASG_BUSY = ("ScalingActivityInProgress", "ResourceInUse", "ResourceContention")


def _retry_delete(fn, what: str, *, gone: tuple[str, ...], gone_text: str = "",
                  busy: tuple = ("DependencyViolation", "ResourceInUse"),
                  attempts: int = 150, interval_s: float = 2.0,
                  leaks: list[str] | None = None) -> bool:
    """Run a teardown call, retrying only the in-use refusals ``busy`` while dependents drain.

    True once done or already gone (a ``gone`` code whose message holds ``gone_text``). Any other
    error stops at once: False, appended to ``leaks`` when given, and the item stays in the estate.
    """
    from botocore.exceptions import ClientError

    last: Exception | None = None
    for _ in range(attempts):
        try:
            fn()
            return True
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] in gone and gone_text in err.get("Message", ""):
                return True
            last = exc
            if err["Code"] not in busy:
                break
        time.sleep(interval_s)
    if leaks is not None:
        leaks.append(f"{what} could not be deleted: {last}")
    return False


def _dismantle(ctx, estate: dict, *, raise_on_leak: bool = False,
               wait_s: float = DISMANTLE_WAIT_S) -> None:
    """Idempotently tear the estate down, fast deletes first; leftovers stay in ``estate`` and
    raise (``raise_on_leak``) or wait for the cleanup net."""
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
            _retry_delete(call, f"auto scaling group {name} ({label})", gone=("ValidationError",),
                          gone_text="not found", busy=_ASG_BUSY, leaks=leaks)
    if estate["subs"] or estate["topics"] or estate["queues"]:
        sns = ctx.client("sns")
        sqs = ctx.client("sqs")
        estate["subs"] = [
            arn for arn in estate["subs"]
            if not _retry_delete(lambda arn=arn: sns.unsubscribe(SubscriptionArn=arn),
                                 f"subscription {arn}", gone=("NotFound",), leaks=leaks)
        ]
        estate["topics"] = [
            arn for arn in estate["topics"]
            if not _retry_delete(lambda arn=arn: sns.delete_topic(TopicArn=arn),
                                 f"topic {arn}", gone=("NotFound",), leaks=leaks)
        ]
        estate["queues"] = [
            url for url in estate["queues"]
            if not _retry_delete(lambda url=url: sqs.delete_queue(QueueUrl=url), f"queue {url}",
                                 gone=("AWS.SimpleQueueService.NonExistentQueue",
                                       "QueueDoesNotExist"), leaks=leaks)
        ]
    ec2 = ctx.client("ec2")
    estate["lts"] = [
        lt for lt in estate["lts"]
        if not _retry_delete(lambda lt=lt: ec2.delete_launch_template(LaunchTemplateName=lt),
                             f"launch template {lt}", attempts=8, interval_s=2,
                             gone=("InvalidLaunchTemplateName.NotFoundException",), leaks=leaks)
    ]

    deadline = time.monotonic() + wait_s
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
                                 gone=("TargetGroupNotFound",), leaks=leaks)
        ]
    estate["subnets"] = [
        sn for sn in estate["subnets"]
        if not _retry_delete(lambda sn=sn: ec2.delete_subnet(SubnetId=sn), f"subnet {sn}",
                             gone=("InvalidSubnetID.NotFound",), leaks=leaks)
    ]
    estate["vpcs"] = [
        vpc for vpc in estate["vpcs"]
        if not _retry_delete(lambda vpc=vpc: ec2.delete_vpc(VpcId=vpc), f"vpc {vpc}",
                             gone=("InvalidVpcID.NotFound",), leaks=leaks)
    ]
    if leaks:
        raise RuntimeError("; ".join(leaks))


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(fn, pred, *, timeout_s, interval_s=1, description="condition", ctx=None):
    """Poll fn() until pred() holds; RAISE with the last observed value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
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
    """A dedicated VPC with `want` subnets in AZs that offer instance_type; an account may have
    no default VPC."""
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
    """A launch template that tags both the instance and its volume at launch."""
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
    """DescribeAutoScalingGroups for one name, paginated."""
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


def _create_target_group(ctx, estate: dict, vpc_id: str) -> str:
    elbv2 = ctx.client("elbv2")
    name = ctx.unique_name("sim2real-xsvc-tg-")[:32].rstrip("-")
    arn = elbv2.create_target_group(
        Name=name, Protocol="HTTP", Port=80, VpcId=vpc_id, TargetType="instance",
        Tags=_tags_kv(),
    )["TargetGroups"][0]["TargetGroupArn"]
    estate["tgs"].append(arn)
    return arn


def _registered(elbv2, tg_arn: str) -> set[str]:
    """The target group's registered-target list (no Targets filter: what IS registered)."""
    return {
        d["Target"]["Id"]
        for d in elbv2.describe_target_health(TargetGroupArn=tg_arn)["TargetHealthDescriptions"]
    }


def _health_of(elbv2, tg_arn: str, instance_id: str) -> dict:
    descs = elbv2.describe_target_health(
        TargetGroupArn=tg_arn, Targets=[{"Id": instance_id}]
    )["TargetHealthDescriptions"]
    assert len(descs) == 1, f"DescribeTargetHealth by id returned {descs!r}"
    return descs[0]["TargetHealth"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
