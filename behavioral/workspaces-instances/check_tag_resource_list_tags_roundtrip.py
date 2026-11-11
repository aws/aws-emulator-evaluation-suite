"""tag-resource-list-tags-roundtrip."""
from __future__ import annotations


from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-resource-list-tags-roundtrip"
GROUP = "data-plane"
SERVICES = ["workspaces-instances"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource adds tags that are then visible via ListTagsForResource, and
    UntagResource removes exactly the requested key while leaving the other tag intact."""
    wsi = ctx.client("workspaces-instances")
    subnet_id, _az = _default_subnet(ctx)
    ami_id = _latest_al2_ami(ctx)
    _ensure_service_linked_role(ctx)

    instance_id = wsi.create_workspace_instance(
        ManagedInstance={"ImageId": ami_id, "InstanceType": "m5.large", "SubnetId": subnet_id},
        Tags=[{"Key": "owner", "Value": "sim2real"}],
    )["WorkspaceInstanceId"]
    ctx.on_cleanup(lambda: _best_effort_delete_instance(wsi, instance_id))

    initial = wsi.list_tags_for_resource(WorkspaceInstanceId=instance_id)["Tags"]
    assert {"Key": "owner", "Value": "sim2real"} in initial, (
        f"expected creation tag owner=sim2real in {initial}"
    )

    wsi.tag_resource(
        WorkspaceInstanceId=instance_id,
        Tags=[{"Key": "environment", "Value": "test"}],
    )
    after_tag = wsi.list_tags_for_resource(WorkspaceInstanceId=instance_id)["Tags"]
    assert {"Key": "owner", "Value": "sim2real"} in after_tag, (
        f"expected owner=sim2real to survive TagResource, got {after_tag}"
    )
    assert {"Key": "environment", "Value": "test"} in after_tag, (
        f"expected environment=test added by TagResource, got {after_tag}"
    )

    wsi.untag_resource(WorkspaceInstanceId=instance_id, TagKeys=["environment"])
    after_untag = wsi.list_tags_for_resource(WorkspaceInstanceId=instance_id)["Tags"]
    assert {"Key": "owner", "Value": "sim2real"} in after_untag, (
        f"expected owner=sim2real to survive UntagResource, got {after_untag}"
    )
    assert not any(t["Key"] == "environment" for t in after_untag), (
        f"expected environment key removed by UntagResource, got {after_untag}"
    )


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to launch a WorkSpace Instance")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnet available in shared network")
    subnet = subnets[0]
    return subnet["SubnetId"], subnet["AvailabilityZone"]


def _ensure_service_linked_role(ctx):
    from botocore.exceptions import ClientError

    try:
        ctx.client("iam").create_service_linked_role(
            AWSServiceName="workspaces-instances.amazonaws.com"
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "InvalidInput":
            raise


def _latest_al2_ami(ctx):
    ssm = ctx.client("ssm")
    resp = ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )
    return resp["Parameter"]["Value"]


def _best_effort_delete_instance(wsi, instance_id, timeout_s=300.0):
    """Delete the instance; already gone is clean, the ConflictException refused while it is
    still Allocating is retried every 2 s for up to 300 s, and any other error raises."""
    import time

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            wsi.delete_workspace_instance(WorkspaceInstanceId=instance_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
