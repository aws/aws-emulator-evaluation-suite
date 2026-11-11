"""create-asg-duplicate-name-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-asg-duplicate-name-fails"
GROUP = 'error-semantics'
SERVICES = ['autoscaling']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a second group with an already-used name raises AlreadyExists and leaves the
    original untouched; once deleting the original frees the name, the identical create
    succeeds and the recreated group is independently observable."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

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

    def _delete_lt(lt_name):
        try:
            ec2.delete_launch_template(LaunchTemplateName=lt_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidLaunchTemplateName.NotFoundException":
                raise

    def _make_lt(instance_type="t3.micro"):
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": _image_id(), "InstanceType": instance_type},
            TagSpecifications=[
                {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
            ],
        )
        ctx.on_cleanup(lambda n=lt_name: _delete_lt(n))
        return lt_name

    def _delete_asg(asg_name):
        try:
            as_.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
        except ClientError as exc:
            err = exc.response["Error"]
            if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
                raise

    def _describe(asg_name):
        return as_.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name]
        )["AutoScalingGroups"]

    def _wait_gone(asg_name, timeout_s=60, interval_s=3):
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if not _describe(asg_name):
                return
            time.sleep(interval_s)
        raise AssertionError(f"{asg_name} was not deleted within {timeout_s}s")

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
            "Tags": [{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(lambda n=asg_name: _delete_asg(n))
        return asg_name

    name = _make_asg(min_size=0, max_size=1, desired_capacity=0)
    lt_name = _make_lt()

    duplicate_kwargs = dict(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=5,
        VPCZoneIdentifier=",".join(_subnet_ids()),
    )

    code, message = _client_error(lambda: as_.create_auto_scaling_group(**duplicate_kwargs))
    assert code == "AlreadyExists", f"expected AlreadyExists, got {code}"
    assert message == (
        f"AutoScalingGroup by this name already exists - A group with the name {name} already exists"
    ), f"expected the exact refusal message, got {message!r}"

    # Effect-absent: the rejected duplicate must not have mutated the original group.
    unchanged = _describe(name)
    assert len(unchanged) == 1, f"expected exactly one group named {name!r}, found {len(unchanged)}"
    assert unchanged[0]["MaxSize"] == 1, (
        f"original group's MaxSize was mutated by the rejected duplicate create: {unchanged[0]['MaxSize']}"
    )

    # Restore: free the name by deleting the original group, then prove deletion via an
    # independent read (not a sleep) before retrying.
    as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    _wait_gone(name)

    # The identical call that failed above now succeeds once the name is free.
    as_.create_auto_scaling_group(**duplicate_kwargs)
    recreated = _describe(name)
    assert len(recreated) == 1, (
        f"expected the identical create call to succeed once {name!r} was freed, got {recreated}"
    )
    assert recreated[0]["MaxSize"] == 5, (
        f"expected the recreated group's MaxSize to be 5, got {recreated[0]['MaxSize']}"
    )

    # Terminal beat: delete the recreated group too and prove it is independently gone.
    as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    _wait_gone(name)


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, because accepting a call AWS refuses is itself the failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
