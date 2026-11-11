"""instance-refresh-rollback-order."""
from __future__ import annotations

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "instance-refresh-rollback-order"
GROUP = 'overly-permissive'
SERVICES = ['autoscaling']


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A refresh with an explicit DesiredConfiguration on a version-pinned group (required for
    rollback) rolls back through InProgress -> RollbackInProgress -> RollbackSuccessful in order,
    and a second rollback after completion is rejected."""
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

    def _subnet_ids():
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        if not subnets:
            raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
        return [s["SubnetId"] for s in sorted(subnets, key=lambda s: s["AvailabilityZone"])[:2]]

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

    def _make_lt_version(lt_name, instance_type="t3.small"):
        resp = ec2.create_launch_template_version(
            LaunchTemplateName=lt_name,
            SourceVersion="1",
            LaunchTemplateData={"InstanceType": instance_type},
        )
        return str(resp["LaunchTemplateVersion"]["VersionNumber"])

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

    def _refresh(name, refresh_id):
        resp = as_.describe_instance_refreshes(
            AutoScalingGroupName=name, InstanceRefreshIds=[refresh_id]
        )
        return resp["InstanceRefreshes"][0]

    def _error(fn):
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        raise AssertionError(
            f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
        )

    lt_name = _make_lt()
    v2 = _make_lt_version(lt_name, instance_type="t3.small")
    name = _make_asg(
        min_size=0,
        max_size=3,
        desired_capacity=2,
        launch_template_name=lt_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "1"},
    )
    _wait_for_in_service(name, 2, timeout_s=420, interval_s=5)

    start_resp = as_.start_instance_refresh(
        AutoScalingGroupName=name,
        Preferences={"MinHealthyPercentage": 90, "InstanceWarmup": 60},
        DesiredConfiguration={"LaunchTemplate": {"LaunchTemplateName": lt_name, "Version": v2}},
    )
    refresh_id = start_resp["InstanceRefreshId"]

    _poll_until(
        lambda: _refresh(name, refresh_id),
        lambda r: r["Status"] in ("InProgress", "Baking"),
        timeout_s=60,
        interval_s=1,
        description=f"refresh {refresh_id} actually InProgress (not just Pending) before rollback",
    )

    rb_resp = as_.rollback_instance_refresh(AutoScalingGroupName=name)
    assert rb_resp.get("InstanceRefreshId") == refresh_id, (
        f"expected RollbackInstanceRefresh to target the in-progress refresh "
        f"{refresh_id!r}, got {rb_resp.get('InstanceRefreshId')!r}"
    )

    statuses: list[str] = []

    def _probe():
        r = _refresh(name, refresh_id)
        statuses.append(r["Status"])
        return r

    final = _poll_until(
        _probe,
        lambda r: r["Status"] in ("RollbackSuccessful", "RollbackFailed"),
        timeout_s=300,
        interval_s=5,
        description=f"refresh {refresh_id} completes its rollback",
    )
    assert final["Status"] == "RollbackSuccessful", (
        f"expected RollbackSuccessful, got {final['Status']!r}: {final.get('StatusReason')}"
    )
    assert "RollbackInProgress" in statuses, (
        f"expected to observe RollbackInProgress before rollback completion, saw {statuses}"
    )

    # Overly-permissive guard: rolling back a refresh that has already finished rolling
    # back must fail — there is no active refresh/rollback left.
    code, message = _error(lambda: as_.rollback_instance_refresh(AutoScalingGroupName=name))
    assert code == "ActiveInstanceRefreshNotFound", (
        f"expected ActiveInstanceRefreshNotFound for a redundant rollback, got {code!r}"
    )
    expected = f"No in progress or baking Instance Refresh found for Auto Scaling group {name}."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
