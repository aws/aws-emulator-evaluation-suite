"""set-desired-capacity-partial-scale-in-keeps-one-of-three-instances."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "set-desired-capacity-partial-scale-in-keeps-one-of-three-instances"
GROUP = 'capacity-management'
SERVICES = ['autoscaling']

#: Public SSM parameter for the latest AL2023 x86_64 AMI.
_CATALOG_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
#: Instance launch/termination waits (bounded convergence).
_INSTANCE_WAIT_S = 120
#: Bounded convergence for the group delete.
_CONVERGE_WAIT_S = 90
#: Bounded retry for a subnet or VPC delete while terminated instances release their interfaces.
_NETWORK_RELEASE_S = 180


#: The runner's deadline for this check (monotonic clock), set as run() starts.
_RUN_END: dict = {}


def _bounded(timeout_s: float) -> float:
    """``timeout_s`` cut to the time the runner leaves this check, so a wait fails with its own
    last observation rather than the runner's timeout."""
    end = _RUN_END.get("t")
    return timeout_s if end is None else max(1.0, min(timeout_s, end - time.monotonic() - 3.0))


def _start_budget(ctx) -> None:
    left = ctx.time_left()
    _RUN_END["t"] = None if left is None else time.monotonic() + left



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
    """SetDesiredCapacity 3 launches three t3.nano instances that run in EC2; lowering it to 1 keeps
    exactly one of them InService and running while EC2 terminates the other two, and the deleted
    group is then absent, unlisted and unmutable."""
    _start_budget(ctx)
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    _NETWORK: list = []

    def _poll_until(probe, pred, timeout_s=120, interval_s=3, description="condition"):
        timeout_s = _bounded(timeout_s)
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
            # Only a missing parameter (GetParameter's ParameterNotFound, empty message) falls
            # back; any other error is a failed prerequisite.
            if (err.get("Code"), err.get("Message") or "") != ("ParameterNotFound", ""):
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
            CidrBlock="10.83.0.0/16", TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_spec}]
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_vpc(VpcId=vpc_id)))
        for i, az in enumerate(zones[:2]):
            subnet_id = ec2.create_subnet(
                VpcId=vpc_id, CidrBlock=f"10.83.{i + 1}.0/24", AvailabilityZone=az,
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

    def _make_lt(instance_type="t3.nano"):
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
            err = exc.response.get("Error", {})
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            got = (err.get("Code"), err.get("Message"))
            want = ("ValidationError", "AutoScalingGroup name not found - null")
            assert got == want, f"{what}: expected {want!r}, got {got!r}"
            assert isinstance(status, int) and 400 <= status < 500, f"{what}: expected an HTTP 4xx, got {status!r}"
            return
        raise AssertionError(f"{what}: expected ValidationError, but the call SUCCEEDED: {result!r}")

    name = _make_asg(min_size=0, max_size=4, desired_capacity=0)
    assert _group_instances(name) == [], f"expected 0 instances at DesiredCapacity=0, got {_group_instances(name)}"

    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=3)
    instances = _poll_until(
        lambda: _group_instances(name),
        lambda ins: len(ins) == 3 and all(i.get("LifecycleState") == "InService" for i in ins),
        timeout_s=_INSTANCE_WAIT_S, interval_s=5,
        description="3 InService instances after SetDesiredCapacity=3",
    )
    ids = sorted(i["InstanceId"] for i in instances)
    assert len(set(ids)) == 3, f"expected 3 distinct group instances, got {len(set(ids))}"
    seen = _poll_until(
        lambda: _ec2_states(ids),
        lambda st: len(st) == 3 and all(i.get("State", {}).get("Name") == "running" for i in st.values()),
        timeout_s=_INSTANCE_WAIT_S, interval_s=5,
        description="EC2 to report all three group instances running",
    )
    for iid, inst in seen.items():
        got = (inst.get("ImageId") == image_id, inst.get("InstanceType"), inst.get("SubnetId") in subnet_ids)
        assert got == (True, "t3.nano", True), (
            f"instance {iid} (catalog AMI, type, in a group subnet): expected (True, 't3.nano', True), got {got!r}"
        )

    # Partial scale-in: exactly one of the three stays, the other two terminate.
    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1)
    kept = _poll_until(
        lambda: _group_instances(name),
        lambda ins: len(ins) == 1 and ins[0].get("LifecycleState") == "InService",
        timeout_s=_INSTANCE_WAIT_S, interval_s=5,
        description="the group to hold exactly one InService instance after SetDesiredCapacity=1",
    )
    kept_id = kept[0]["InstanceId"]
    assert kept_id in ids, f"the remaining instance is not one of the three launched (got one outside, {len(ids)} launched)"
    gone = [i for i in ids if i != kept_id]
    final = _poll_until(
        lambda: _ec2_states(ids),
        lambda st: len(st) == 3 and all(st[i].get("State", {}).get("Name") == "terminated" for i in gone),
        timeout_s=_INSTANCE_WAIT_S, interval_s=5,
        description="EC2 to report the two scaled-in instances terminated",
    )
    assert final[kept_id]["State"]["Name"] == "running", (
        f"the kept instance must still run in EC2, got {final[kept_id]['State']['Name']!r}"
    )
    group = _describe_group(name)
    assert (group["DesiredCapacity"], len(group.get("Instances", []))) == (1, 1), (
        f"group (DesiredCapacity, instance count) after scale-in: expected (1, 1), got "
        f"{(group['DesiredCapacity'], len(group.get('Instances', [])))!r}"
    )

    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=0)
    _poll_until(
        lambda: _ec2_states([kept_id]),
        lambda st: st.get(kept_id, {}).get("State", {}).get("Name") == "terminated",
        timeout_s=_INSTANCE_WAIT_S, interval_s=5,
        description="EC2 to report the last instance terminated after scale-in to 0",
    )
    _poll_until(
        lambda: _group_instances(name), lambda ins: ins == [], timeout_s=_INSTANCE_WAIT_S,
        interval_s=5, description="the group to hold no instances after scale-in to 0",
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
