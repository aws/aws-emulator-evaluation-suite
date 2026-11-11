"""delete-asg-in-use-without-force-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-asg-in-use-without-force-fails"
GROUP = 'overly-permissive'
SERVICES = ['autoscaling']

#: Public SSM parameter resolving the AMI.
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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAutoScalingGroup without ForceDelete rejects a group that still has an instance; once
    it is scaled to zero and the instance is terminated, the identical call succeeds and the group
    is absent, unlisted and unmutable.
    """
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
        """The SSM-parameter AMI, or the newest available amazon or own x86_64 image when the
        parameter is absent."""
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

    def _make_lt(instance_type="t3.micro"):
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": _image_id(), "InstanceType": instance_type},
            TagSpecifications=[
                {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
            ],
        )
        ctx.on_cleanup(lambda n=lt_name: ec2.delete_launch_template(LaunchTemplateName=n))
        return lt_name

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
            "VPCZoneIdentifier": ",".join(_subnet_ids()),
            "HealthCheckGracePeriod": 0,
            "Tags": [{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)

        def _cleanup(n=asg_name):
            try:
                as_.delete_auto_scaling_group(AutoScalingGroupName=n, ForceDelete=True)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ValidationError":
                    raise

        ctx.on_cleanup(_cleanup)
        return asg_name

    def _wait_for_in_service(name, count, timeout_s=_INSTANCE_WAIT_S, interval_s=5):
        def _pred(ins):
            return (
                bool(ins)
                and len(ins) == count
                and all(i.get("LifecycleState") == "InService" for i in ins)
            )
        return _poll_until(lambda: _group_instances(name), _pred, timeout_s, interval_s)

    name = _make_asg(min_size=0, max_size=1, desired_capacity=1)
    in_service = _wait_for_in_service(name, 1, interval_s=5)
    instance_ids = [i["InstanceId"] for i in in_service]

    def _attempt_delete():
        try:
            as_.delete_auto_scaling_group(AutoScalingGroupName=name)
            return None
        except ClientError as exc:
            return {
                "Code": exc.response.get("Error", {}).get("Code"),
                "Message": exc.response.get("Error", {}).get("Message"),
                "HTTPStatusCode": exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            }

    # The instance reading InService does not guarantee its launch activity has itself
    # settled: real AWS can still answer ScalingActivityInProgress for a few seconds after.
    # Retry past that transient before asserting the terminal "group not empty" rejection.
    err = _poll_until(
        _attempt_delete,
        lambda e: e is None or e["Code"] != "ScalingActivityInProgress",
        timeout_s=90,
        interval_s=5,
        description="delete rejection to settle past ScalingActivityInProgress",
    )
    assert err is not None, "DeleteAutoScalingGroup without ForceDelete SUCCEEDED on a group with an instance"
    assert err["Code"] == "ResourceInUse", f"expected ResourceInUse, got {err['Code']!r}"
    assert err["Message"] == "You cannot delete an AutoScalingGroup while there are instances or pending Spot instance request(s) still in the group.", (
        f'expected the exact ResourceInUse message AWS returns, got {err["Message"]!r}'
    )
    assert isinstance(err["HTTPStatusCode"], int) and 400 <= err["HTTPStatusCode"] < 500, (
        f"expected an HTTP 4xx for ResourceInUse, got {err['HTTPStatusCode']!r}"
    )
    assert (err["Message"] or "").strip(), f"expected a non-empty ResourceInUse message, got {err!r}"

    # The group must still exist after the rejected delete.
    assert _describe_group(name) is not None, "rejected delete must not remove the group"

    # Positive control: remove the instance, then the identical plain call must succeed.
    as_.update_auto_scaling_group(AutoScalingGroupName=name, MinSize=0, DesiredCapacity=0)

    def _ec2_states():
        res = ec2.describe_instances(InstanceIds=instance_ids)
        return [i.get("State", {}).get("Name") for r in res.get("Reservations", []) for i in r.get("Instances", [])]

    _poll_until(
        _ec2_states,
        lambda st: len(st) == len(instance_ids) and all(x == "terminated" for x in st),
        timeout_s=_INSTANCE_WAIT_S,
        interval_s=5,
        description="EC2 to report the scaled-in group's instance terminated",
    )
    _poll_until(
        lambda: _group_instances(name),
        lambda ins: not ins,
        timeout_s=_INSTANCE_WAIT_S,
        interval_s=5,
        description="the scaled-in group to hold no instances",
    )
    # The scale-in activity can still read in progress briefly after its instance terminates.
    err = _poll_until(
        _attempt_delete,
        lambda e: e is None or e["Code"] != "ScalingActivityInProgress",
        timeout_s=90,
        interval_s=5,
        description="the plain delete of the empty group to settle past ScalingActivityInProgress",
    )
    assert err is None, (
        f"DeleteAutoScalingGroup without ForceDelete on the emptied group: expected success, got {err!r}"
    )
    # Beat 1: the by-name describe reports the miss in-band (bounded convergence).
    _poll_until(
        lambda: _describe_group(name),
        lambda g: g is None,
        timeout_s=_CONVERGE_WAIT_S,
        interval_s=5,
        description="group removal after the plain delete",
    )
    # Beat 2: absent from the listing filtered to its own tag.
    tagged = [
        g.get("AutoScalingGroupName")
        for page in as_.get_paginator("describe_auto_scaling_groups").paginate(
            Filters=[{"Name": "tag:sim2real", "Values": [CHECK]}]
        )
        for g in page.get("AutoScalingGroups", [])
    ]
    assert name not in tagged, f"deleted group still listed under tag sim2real={CHECK}: {tagged!r}"
    # Beat 3: a mutation on the dead name is refused.
    try:
        as_.update_auto_scaling_group(AutoScalingGroupName=name, MaxSize=2)
        dead = None
    except ClientError as exc:
        dead = exc.response
    assert dead is not None, "UpdateAutoScalingGroup on the deleted group SUCCEEDED"
    assert dead.get("Error", {}).get("Code") == "ValidationError", (
        f"expected ValidationError updating the deleted group, got {dead.get('Error')!r}"
    )
    assert dead.get("Error", {}).get("Message") == "AutoScalingGroup name not found - null", (
        f'expected the exact ValidationError message AWS returns, got {dead.get("Error", {}).get("Message")!r}'
    )
    dead_status = dead.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert isinstance(dead_status, int) and 400 <= dead_status < 500, (
        f"expected an HTTP 4xx updating the deleted group, got {dead_status!r}"
    )
    assert (dead.get("Error", {}).get("Message") or "").strip(), (
        f"expected a non-empty message updating the deleted group, got {dead.get('Error')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
