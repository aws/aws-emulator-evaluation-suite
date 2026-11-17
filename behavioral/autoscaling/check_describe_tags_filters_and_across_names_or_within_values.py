"""describe-tags-filters-and-across-names-or-within-values."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-tags-filters-and-across-names-or-within-values"
GROUP = "tags"
SERVICES = ["autoscaling", "ec2", "ssm"]


def _ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _make_group(ctx, as_, ec2, ami, color, shape) -> str:
    lt_name = ctx.unique_name("sim2real-behav-asg-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    name = ctx.unique_name("sim2real-behav-asg-")
    as_.create_auto_scaling_group(
        AutoScalingGroupName=name,
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        AvailabilityZones=[ctx.network().availability_zones[0]],
        Tags=[
            {"Key": "behav-color", "Value": color, "PropagateAtLaunch": False},
            {"Key": "behav-shape", "Value": shape, "PropagateAtLaunch": False},
        ],
    )
    ctx.on_cleanup(
        lambda: as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    )
    return name


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeTags joins several Filters with AND, and joins the Values inside one Filter
    with OR: a key+value pair isolates one group, and a Values list reaches several groups."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami = _ami(ctx)

    red = _make_group(ctx, as_, ec2, ami, color="red", shape="round")
    blue = _make_group(ctx, as_, ec2, ami, color="blue", shape="round")
    scope = [{"Name": "auto-scaling-group", "Values": [red, blue]}]

    def scoped_tags(*extra_filters):
        return as_.describe_tags(Filters=scope + list(extra_filters))["Tags"]

    # Two Filter entries (key AND value) isolate the one group matching both.
    and_matches = scoped_tags(
        {"Name": "key", "Values": ["behav-color"]}, {"Name": "value", "Values": ["red"]}
    )
    and_resources = {t["ResourceId"] for t in and_matches}
    assert and_resources == {red}, (
        f"key=behav-color AND value=red must isolate the red group, got {sorted(and_resources)!r}"
    )

    # One Filter with two Values reaches both groups (OR within the Values list).
    or_matches = scoped_tags({"Name": "value", "Values": ["red", "blue"]})
    or_resources = {t["ResourceId"] for t in or_matches}
    assert or_resources == {red, blue}, (
        f"value in [red, blue] must reach both groups, got {sorted(or_resources)!r}"
    )
    or_keys = {t["Key"] for t in or_matches}
    assert or_keys == {"behav-color"}, (
        f"the value filter must match only the color tag, not shape: got keys {sorted(or_keys)!r}"
    )

    # A value that exists but not paired with the requested key matches nothing.
    empty_matches = scoped_tags(
        {"Name": "key", "Values": ["behav-color"]}, {"Name": "value", "Values": ["round"]}
    )
    assert empty_matches == [], f"key=behav-color AND value=round matches no tag, got {empty_matches!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
