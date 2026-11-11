"""instance-refresh-full-lifecycle."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "instance-refresh-full-lifecycle"
GROUP = 'instance-refresh'
SERVICES = ['autoscaling']

REFRESH_TERMINAL_STATUSES = {
    "Successful",
    "Failed",
    "Cancelled",
    "RollbackFailed",
    "RollbackSuccessful",
}

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartInstanceRefresh enters Pending/InProgress and advances monotonically to a
    Successful terminal status."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    def _poll_until(probe, pred, timeout_s=120, interval_s=3, description="condition"):
        import time
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if pred(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s; last result: {last!r}")

    def _image_id():
        param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        try:
            return ssm.get_parameter(Name=param)["Parameter"]["Value"]
        except Exception:
            imgs = sorted(
                ec2.describe_images(
                    Owners=["amazon"],
                    Filters=[
                        {"Name": "name", "Values": ["al2023-ami-kernel-default-x86_64*"]},
                        {"Name": "state", "Values": ["available"]},
                    ],
                ).get("Images", []),
                key=lambda i: i.get("CreationDate", ""),
            )
            if not imgs:
                raise AssertionError("no Amazon Linux 2023 AMI available in this region")
            return imgs[-1]["ImageId"]

    def _describe_group(name):
        groups = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name]).get(
            "AutoScalingGroups", []
        )
        return groups[0] if groups else None

    def _group_instances(name):
        g = _describe_group(name)
        return g.get("Instances", []) if g else []

    def _describe_refresh(asg_name, refresh_id):
        refreshes = as_.describe_instance_refreshes(
            AutoScalingGroupName=asg_name, InstanceRefreshIds=[refresh_id]
        ).get("InstanceRefreshes", [])
        return refreshes[0] if refreshes else None

    _MANAGED_TAGS = {"sim2real": "as-instance-refresh-full-lifecycle"}

    def _make_lt(instance_type="t3.micro"):
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={
                "ImageId": _image_id(),
                "InstanceType": instance_type,
                "TagSpecifications": [
                    {"ResourceType": "instance", "Tags": [
                        {"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()
                    ]},
                ],
            },
            TagSpecifications=[{"ResourceType": "launch-template", "Tags": [
                {"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()
            ]}],
        )
        ctx.on_cleanup(lambda n=lt_name: ec2.delete_launch_template(LaunchTemplateName=n))
        return lt_name

    _vpc_id, subnet_id = _own_vpc_and_subnet(ctx, ec2)

    def _make_asg(min_size=0, max_size=1, desired_capacity=0, launch_template_name=None, **kwargs):
        if launch_template_name is None:
            launch_template_name = _make_lt()
        asg_name = ctx.unique_name("sim2real-behav-as-grp-")
        params = {
            "AutoScalingGroupName": asg_name,
            "LaunchTemplate": {"LaunchTemplateName": launch_template_name, "Version": "$Latest"},
            "MinSize": min_size,
            "MaxSize": max_size,
            "DesiredCapacity": desired_capacity,
            "VPCZoneIdentifier": subnet_id,
            "HealthCheckGracePeriod": 0,
            "Tags": [
                {"Key": k, "Value": v, "PropagateAtLaunch": True}
                for k, v in _MANAGED_TAGS.items()
            ],
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(
            lambda n=asg_name: as_.delete_auto_scaling_group(
                AutoScalingGroupName=n, ForceDelete=True
            )
        )
        return asg_name

    def _wait_for_in_service(name, count, timeout_s=420, interval_s=5):
        def _pred(ins):
            return (
                bool(ins)
                and len(ins) == count
                and all(i.get("LifecycleState") == "InService" for i in ins)
            )
        return _poll_until(lambda: _group_instances(name), _pred, timeout_s, interval_s)

    name = _make_asg(min_size=0, max_size=2, desired_capacity=1)
    before = _wait_for_in_service(name, 1, timeout_s=420, interval_s=5)
    original_ids = {i["InstanceId"] for i in before}

    resp = as_.start_instance_refresh(
        AutoScalingGroupName=name,
        Preferences={"MinHealthyPercentage": 0, "InstanceWarmup": 0, "SkipMatching": False},
    )
    refresh_id = resp["InstanceRefreshId"]
    assert refresh_id, "StartInstanceRefresh must return a non-empty InstanceRefreshId"

    # A best-effort safety net: if an assertion below raises before the refresh reaches a
    # terminal status, cancel it so ASG teardown (registered earlier, so it runs AFTER this)
    # isn't left racing an in-flight refresh.
    def _safe_cancel():
        try:
            as_.cancel_instance_refresh(AutoScalingGroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ActiveInstanceRefreshNotFound":
                raise
    ctx.on_cleanup(_safe_cancel)

    # The refresh must be immediately visible in a non-terminal state with metadata attached.
    initial = _describe_refresh(name, refresh_id)
    assert initial is not None, "refresh must be describable right after being started"
    assert initial["AutoScalingGroupName"] == name, (
        f"describe_instance_refreshes reported group {initial['AutoScalingGroupName']!r}, "
        f"expected {name!r}"
    )
    assert initial["InstanceRefreshId"] == refresh_id, (
        f"describe_instance_refreshes reported id {initial['InstanceRefreshId']!r}, "
        f"expected {refresh_id!r}"
    )
    assert initial["Status"] in ("Pending", "InProgress"), \
        f"a just-started refresh must be Pending/InProgress, got {initial['Status']}"

    # Sample repeatedly over real elapsed time (rather than a single sleep-then-check) so the
    # docstring's "advances monotonically toward completion" is measured, not assumed: the
    # reported PercentageComplete must never regress, and the refresh must actually reach a
    # TERMINAL status -- leaving Pending/InProgress once is not "completion".
    samples = []

    def _sample():
        r = _describe_refresh(name, refresh_id)
        if r is not None:
            samples.append(r)
        return r

    terminal = _poll_until(
        _sample,
        lambda r: r is not None and r["Status"] in REFRESH_TERMINAL_STATUSES,
        timeout_s=900, interval_s=5,
        description=f"instance refresh {refresh_id} reaches a terminal status",
    )
    percentages = [s["PercentageComplete"] for s in samples if s.get("PercentageComplete") is not None]
    assert percentages == sorted(percentages), (
        f"PercentageComplete must never regress across the refresh's lifetime: {percentages}"
    )
    assert terminal["Status"] == "Successful", (
        f"a happy-path refresh (MinHealthyPercentage=0, healthy AMI, no conflicting change) "
        f"must complete Successful, got {terminal['Status']!r} ({terminal.get('StatusReason')!r})"
    )
    assert terminal.get("PercentageComplete") == 100, (
        f"a Successful refresh must report PercentageComplete=100, got "
        f"{terminal.get('PercentageComplete')!r}"
    )

    # The terminal read is a consequence at an independent destination: DescribeAutoScalingGroups,
    # a different operation than the one that started the refresh. A target that fabricates
    # Successful/100% without ever replacing the instance is caught here.
    after = _poll_until(
        lambda: _group_instances(name),
        lambda ins: bool(ins) and len(ins) == 1 and ins[0]["LifecycleState"] == "InService",
        timeout_s=180, interval_s=5,
        description="the group holds exactly one InService instance after the refresh",
    )
    new_ids = {i["InstanceId"] for i in after}
    assert new_ids.isdisjoint(original_ids), (
        f"the refresh reported Successful but did not replace the instance: "
        f"{sorted(new_ids & original_ids)} survived"
    )


def _own_vpc_and_subnet(ctx, ec2, instance_type="t3.micro", cidr="10.81.0.0/16",
                        subnet_cidr="10.81.1.0/24"):
    """A VPC and one subnet this check creates, in an available AZ that offers
    ``instance_type``. Each create registers its cleanup immediately."""
    tag = [{"Key": "sim2real", "Value": CHECK}]
    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": tag}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}])["InstanceTypeOfferings"]}
    zones = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert zones, f"no available AZ offers {instance_type!r}"
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=subnet_cidr, AvailabilityZone=zones[0],
                                  TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}]
                                  )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the suite's cleanup budget.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
