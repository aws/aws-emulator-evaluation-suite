"""set-desired-capacity-launches-instances."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "set-desired-capacity-launches-instances"
GROUP = 'capacity-management'
SERVICES = ['autoscaling']

#: Public SSM parameter for the latest AL2023 x86_64 AMI.
_CATALOG_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
#: Instance launch/termination waits (bounded convergence).
_INSTANCE_WAIT_S = 200
#: Bounded convergence for the group delete.
_CONVERGE_WAIT_S = 200
#: Bounded retry for a subnet or VPC delete while terminated instances release their interfaces.
_NETWORK_RELEASE_S = 180


def _retry_dependency(fn, timeout_s=_NETWORK_RELEASE_S):
    """Teardown: retry ``fn`` through DependencyViolation (bounded); not-found means already gone."""
    import time
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code.endswith(".NotFound"):
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetDesiredCapacity drives the real instance count: both instances reach InService and run in
    EC2 from the resolved AMI, scale-in to 0 terminates them, and the deleted group is then absent,
    unlisted and unmutable."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    _NETWORK: list = []

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
        """The public AL2023 parameter's AMI, or the newest available amazon or own x86_64 image
        when the parameter is absent."""
        try:
            return ssm.get_parameter(Name=_CATALOG_AMI_PARAM)["Parameter"]["Value"]
        except ClientError as exc:
            err = exc.response["Error"]
            # Only a missing parameter falls back; any other error is a failed prerequisite.
            if err["Code"] != "ParameterNotFound":
                raise AssertionError(
                    f"prerequisite catalog-ami: GetParameter({_CATALOG_AMI_PARAM}) failed: {exc}"
                ) from exc
        images = ctx.client("ec2").describe_images(
            Owners=["amazon", "self"],
            Filters=[
                {"Name": "architecture", "Values": ["x86_64"]},
                {"Name": "state", "Values": ["available"]},
            ],
        )["Images"]
        if not images:
            raise AssertionError(
                f"prerequisite catalog-ami: {_CATALOG_AMI_PARAM} is absent and DescribeImages "
                "lists no available amazon or own x86_64 image"
            )
        return max(images, key=lambda i: i.get("CreationDate", ""))["ImageId"]

    def _subnet_ids():
        """Two subnets in two AZs of the check's own VPC; teardown retries the deletes while the
        group's terminated instances release their network interfaces."""
        if _NETWORK:
            return _NETWORK
        zones = sorted(
            z["ZoneName"]
            for z in ec2.describe_availability_zones(
                Filters=[{"Name": "state", "Values": ["available"]}]
            )["AvailabilityZones"]
            if z.get("ZoneType", "availability-zone") == "availability-zone"
        )
        assert len(zones) >= 2, f"region {ctx.region} reports fewer than two available AZs: {zones!r}"
        tag_spec = [{"Key": "sim2real", "Value": CHECK}]
        vpc_id = ec2.create_vpc(
            CidrBlock="10.81.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_spec}]
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
        for i, az in enumerate(zones[:2]):
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=f"10.81.{i + 1}.0/24", AvailabilityZone=az,
                TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_spec}],
            )["Subnet"]["SubnetId"]
            ctx.on_cleanup(lambda s=subnet_id: _retry_dependency(lambda: ec2.delete_subnet(SubnetId=s)))
            _NETWORK.append(subnet_id)
        return _NETWORK

    def _describe_group(name):
        groups = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name]).get(
            "AutoScalingGroups", []
        )
        return groups[0] if groups else None

    def _group_instances(name):
        g = _describe_group(name)
        return g.get("Instances", []) if g else []

    image_id = _image_id()

    def _make_lt(instance_type="t3.micro"):
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": image_id, "InstanceType": instance_type},
            TagSpecifications=[
                {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
            ],
        )
        ctx.on_cleanup(lambda n=lt_name: ec2.delete_launch_template(LaunchTemplateName=n))
        return lt_name

    def _teardown_asg(name):
        # The check deletes its own group; teardown only covers a run that stops before that.
        if _describe_group(name) is None:
            return
        # ForceDelete alone can outrun the 60s cleanup budget while instances are still
        # terminating, so drain the group's bounds to zero first.
        try:
            as_.update_auto_scaling_group(
                AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ValidationError":
                raise
        as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)

    subnet_ids = _subnet_ids()

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
            "VPCZoneIdentifier": ",".join(subnet_ids),
            "HealthCheckGracePeriod": 0,
            "Tags": [{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(lambda n=asg_name: _teardown_asg(n))
        return asg_name

    def _ec2_states(ids):
        res = ec2.describe_instances(InstanceIds=ids)
        return {i["InstanceId"]: i for r in res.get("Reservations", []) for i in r.get("Instances", [])}

    def _expect_not_found(fn, what):
        try:
            result = fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            message2 = exc.response.get("Error", {}).get("Message")
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            message = exc.response.get("Error", {}).get("Message") or ""
            assert code == "ValidationError", f"{what}: expected ValidationError, got {code!r}"
            assert message2 == "AutoScalingGroup name not found - null", (
                f"expected the exact ValidationError message AWS returns, got {message2!r}"
            )
            assert isinstance(status, int) and 400 <= status < 500, f"{what}: expected an HTTP 4xx, got {status!r}"
            assert message.strip(), f"{what}: expected a non-empty message, got {message!r}"
            return
        raise AssertionError(f"{what}: expected ValidationError, but the call SUCCEEDED: {result!r}")

    name = _make_asg(min_size=0, max_size=3, desired_capacity=0)
    setup_instances = _group_instances(name)
    assert setup_instances == [], f"expected 0 instances at DesiredCapacity=0, got {setup_instances}"

    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=2)

    # Terminal state: both instances InService (no intermediate state is required).
    instances = _poll_until(
        lambda: _group_instances(name),
        lambda ins: len(ins) == 2 and all(i.get("LifecycleState") == "InService" for i in ins),
        timeout_s=_INSTANCE_WAIT_S, interval_s=5,
        description="2 InService instances after SetDesiredCapacity",
    )
    assert len(instances) == 2, f"expected 2 instances after SetDesiredCapacity, got {len(instances)}"

    group = _describe_group(name)
    assert group["DesiredCapacity"] == 2, (
        f"expected DesiredCapacity to remain 2 on independent read, got {group['DesiredCapacity']}"
    )

    # Independent read in EC2: the instances really run, from the resolved AMI, where placed.
    ids = sorted(i["InstanceId"] for i in instances)
    # Cross-service read: EC2's view may reach running a moment after Auto Scaling's InService.
    seen = _poll_until(
        lambda: _ec2_states(ids),
        lambda st: len(st) == 2 and all(i.get("State", {}).get("Name") == "running" for i in st.values()),
        timeout_s=_INSTANCE_WAIT_S, interval_s=5,
        description="EC2 to report both group instances running",
    )
    assert sorted(seen) == ids, f"EC2 must describe both group instances {ids}, got {sorted(seen)}"
    for iid, inst in seen.items():
        state = inst.get("State", {}).get("Name")
        assert state == "running", f"instance {iid}: expected EC2 state running, got {state!r}"
        assert inst.get("ImageId") == image_id, (
            f"instance {iid}: expected the catalog AMI {image_id!r}, got {inst.get('ImageId')!r}"
        )
        assert inst.get("InstanceType") == "t3.micro", (
            f"instance {iid}: expected InstanceType t3.micro, got {inst.get('InstanceType')!r}"
        )
        tags_map = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
        assert tags_map.get("sim2real") == CHECK, (
            f"instance {iid}: expected the propagated tag sim2real={CHECK}, got {tags_map!r}"
        )
        assert inst.get("SubnetId") in subnet_ids, (
            f"instance {iid}: expected a subnet of the group {subnet_ids}, got {inst.get('SubnetId')!r}"
        )

    # Scale-in really terminates the instances.
    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=0)
    _poll_until(
        lambda: _group_instances(name), lambda ins: ins == [], timeout_s=_INSTANCE_WAIT_S,
        interval_s=5, description="the group to hold no instances after scale-in to 0",
    )
    _poll_until(
        lambda: _ec2_states(ids),
        lambda st: all(i.get("State", {}).get("Name") == "terminated" for i in st.values()) and len(st) == 2,
        timeout_s=_INSTANCE_WAIT_S, interval_s=5,
        description="EC2 to report both scaled-in instances terminated",
    )

    def _tagged():
        return [
            g.get("AutoScalingGroupName")
            for page in as_.get_paginator("describe_auto_scaling_groups").paginate(
                Filters=[{"Name": "tag:sim2real", "Values": [CHECK]}]
            )
            for g in page.get("AutoScalingGroups", [])
        ]

    assert name in _tagged(), f"group {name} not listed under tag sim2real={CHECK} before the delete"
    as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    # Beat 1: the by-name describe reports the miss in-band.
    _poll_until(
        lambda: _describe_group(name), lambda g: g is None, timeout_s=_CONVERGE_WAIT_S, interval_s=3,
        description="the deleted group to leave DescribeAutoScalingGroups",
    )
    # Beat 2: absent from the listing filtered to its own tag.
    tagged = _tagged()
    assert name not in tagged, f"deleted group still listed under tag sim2real={CHECK}: {tagged!r}"
    # Beat 3: a mutation on the dead name is refused.
    _expect_not_found(
        lambda: as_.update_auto_scaling_group(AutoScalingGroupName=name, MaxSize=2),
        "UpdateAutoScalingGroup on the deleted group",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
