"""custom-component-ec2-only-and-exclusive."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "custom-component-ec2-only-and-exclusive"
GROUP = "component-grouping"
SERVICES = ["application-insights"]

_AL2023_SSM_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_CANDIDATE_INSTANCE_TYPES = ("t3.micro", "t2.micro", "t3a.micro")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _resolve_ami(ec2, ssm) -> str:
    try:
        return ssm.get_parameter(Name=_AL2023_SSM_PARAM)["Parameter"]["Value"]
    except Exception:  # noqa: BLE001 - fall back to a direct image lookup
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
                {"Name": "architecture", "Values": ["x86_64"]},
                {"Name": "root-device-type", "Values": ["ebs"]},
            ],
        )["Images"]
        assert images, "no Amazon Linux 2023 x86_64 AMI is available in this region"
        return max(images, key=lambda i: i["CreationDate"])["ImageId"]


def _pick_subnet_and_type(ec2, network) -> tuple[str, str]:
    """A (subnet_id, instance_type) this account can actually launch."""
    offered: set[tuple[str, str]] = set()
    resp = ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[
            {"Name": "instance-type", "Values": list(_CANDIDATE_INSTANCE_TYPES)},
            {"Name": "location", "Values": network.availability_zones},
        ],
    )
    offered = {(o["InstanceType"], o["Location"]) for o in resp["InstanceTypeOfferings"]}
    for itype in _CANDIDATE_INSTANCE_TYPES:
        for az, subnet_id in network.subnets.items():
            if (itype, az) in offered:
                return subnet_id, itype
    raise AssertionError(
        f"no candidate instance type {_CANDIDATE_INSTANCE_TYPES} is offered in "
        f"{network.availability_zones!r}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last={last!r}")


def _component_names(ai, group_name: str) -> set[str]:
    return {
        c["ComponentName"]
        for c in ai.list_components(ResourceGroupName=group_name)["ApplicationComponentList"]
    }


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CreateComponent only groups EC2 instances, and a resource already grouped by one
    custom component cannot be grouped by a second; deleting the first frees it for reuse.

    Reference: https://docs.aws.amazon.com/application-insights/latest/APIReference/API_CreateComponent.html
    """
    s3 = ctx.client("s3")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    rg = ctx.client("resource-groups")
    ai = ctx.client("application-insights")

    tag_key = ctx.unique_name("sim2real-behav-ai-tag-")
    bucket = ctx.unique_name("sim2real-behav-ai-bkt-")

    s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket), "NoSuchBucket"))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": tag_key, "Value": "1"}]})
    bucket_arn = f"arn:aws:s3:::{bucket}"

    group_name = ctx.unique_name("sim2real-behav-ai-group-")
    rg.create_group(
        Name=group_name,
        ResourceQuery={
            "Type": "TAG_FILTERS_1_0",
            "Query": json.dumps(
                {
                    "ResourceTypeFilters": ["AWS::AllSupported"],
                    "TagFilters": [{"Key": tag_key, "Values": ["1"]}],
                }
            ),
        },
    )
    ctx.on_cleanup(_teardown(lambda: rg.delete_group(GroupName=group_name), "NotFoundException"))

    network = ctx.network()
    subnet_id, instance_type = _pick_subnet_and_type(ec2, network)
    ami = _resolve_ami(ec2, ssm)
    instance_id = ec2.run_instances(
        ImageId=ami,
        InstanceType=instance_type,
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        TagSpecifications=[
            {"ResourceType": "instance", "Tags": [{"Key": tag_key, "Value": "1"}]},
            {"ResourceType": "volume", "Tags": [{"Key": tag_key, "Value": "1"}]},
        ],
    )["Instances"][0]["InstanceId"]
    ctx.on_cleanup(lambda: ec2.terminate_instances(InstanceIds=[instance_id]))
    instance_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:instance/{instance_id}"

    ai.create_application(ResourceGroupName=group_name, AutoConfigEnabled=False)
    ctx.on_cleanup(
        _teardown(
            lambda: ai.delete_application(ResourceGroupName=group_name), "ResourceNotFoundException"
        )
    )

    names = _poll_until(
        lambda: _component_names(ai, group_name),
        lambda n: bucket_arn in n and instance_arn in n,
        timeout_s=240,
        interval_s=10,
        description="the bucket and the instance to be auto-discovered as components",
    )
    assert names == {bucket_arn, instance_arn}, f"unexpected discovered components {names!r}"

    # Grouping a non-EC2 resource into a custom component is refused outright.
    code, message = _error(
        lambda: ai.create_component(
            ResourceGroupName=group_name,
            ComponentName=ctx.unique_name("sim2real-behav-ai-comp-"),
            ResourceList=[bucket_arn],
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == "Only EC2 Instance can be grouped.", f"unexpected message {message!r}"
    assert _component_names(ai, group_name) == {bucket_arn, instance_arn}, (
        "the rejected call must not have created any custom component"
    )

    # Grouping the EC2 instance succeeds, and absorbs its attached EBS volume too.
    custom_name = ctx.unique_name("sim2real-behav-ai-comp-")
    ai.create_component(
        ResourceGroupName=group_name, ComponentName=custom_name, ResourceList=[instance_arn]
    )
    ctx.on_cleanup(
        _teardown(
            lambda: ai.delete_component(ResourceGroupName=group_name, ComponentName=custom_name),
            "ResourceNotFoundException",
        )
    )
    volumes = ec2.describe_volumes(
        Filters=[{"Name": "attachment.instance-id", "Values": [instance_id]}]
    )["Volumes"]
    assert volumes, f"instance {instance_id!r} has no attached volume to verify against"
    volume_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:volume/{volumes[0]['VolumeId']}"

    described = ai.describe_component(ResourceGroupName=group_name, ComponentName=custom_name)
    resource_list = set(described["ResourceList"])
    assert instance_arn in resource_list, (
        f"ResourceList {resource_list!r} is missing the instance itself"
    )
    assert volume_arn in resource_list, (
        f"ResourceList {resource_list!r} does not include the instance's own attached volume {volume_arn!r}: "
        "grouping an EC2 instance should absorb its attached EBS volume"
    )
    assert _component_names(ai, group_name) == {bucket_arn, custom_name}, (
        "the instance's standalone default component must disappear once it joins a custom one"
    )

    # The instance is now exclusively owned: a second custom component naming it is refused.
    second_name = ctx.unique_name("sim2real-behav-ai-comp-")
    code, message = _error(
        lambda: ai.create_component(
            ResourceGroupName=group_name, ComponentName=second_name, ResourceList=[instance_arn]
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}: {message!r}"
    assert message == f"Component {instance_arn} is grouped in another component.", (
        f"unexpected message {message!r}"
    )
    code, message = _error(
        lambda: ai.describe_component(ResourceGroupName=group_name, ComponentName=second_name)
    )
    assert code == "ResourceNotFoundException", (
        f"the refused CreateComponent must not have created {second_name!r}, got {code}: {message!r}"
    )

    # Releasing the first grouping frees the instance for a fresh one.
    ai.delete_component(ResourceGroupName=group_name, ComponentName=custom_name)
    _poll_until(
        lambda: _component_names(ai, group_name),
        lambda n: instance_arn in n,
        timeout_s=120,
        interval_s=5,
        description="the instance to revert to its own default component after release",
    )

    third_name = ctx.unique_name("sim2real-behav-ai-comp-")
    ai.create_component(
        ResourceGroupName=group_name, ComponentName=third_name, ResourceList=[instance_arn]
    )
    ctx.on_cleanup(
        _teardown(
            lambda: ai.delete_component(ResourceGroupName=group_name, ComponentName=third_name),
            "ResourceNotFoundException",
        )
    )
    assert _component_names(ai, group_name) == {bucket_arn, third_name}, (
        "the freed instance must be groupable again after the first component was deleted"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
