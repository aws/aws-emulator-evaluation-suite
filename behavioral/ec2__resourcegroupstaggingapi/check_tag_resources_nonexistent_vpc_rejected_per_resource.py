"""tag-resources-nonexistent-vpc-rejected-per-resource."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resources-nonexistent-vpc-rejected-per-resource"
GROUP = "overly-permissive"
SERVICES = ["ec2", "resourcegroupstaggingapi"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A TagResources batch naming one live VPC and one well-formed but never-created VPC ARN
    returns 200, tags the live one, and reports the absent one in FailedResourcesMap with EC2's
    own InvalidVpcID.NotFound -- never silently accepted and never a whole-batch failure.
    """
    ec2 = ctx.client("ec2")
    rgt = ctx.client("resourcegroupstaggingapi")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.81.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc",
                            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    live_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:vpc/{vpc_id}"

    # A syntactically valid but never-created id would fail EC2's own ID-format validation with
    # a generic InvalidID, so the absent id is a real one, created and deleted right away.
    ghost_id = ec2.create_vpc(CidrBlock="10.83.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=ghost_id), "InvalidVpcID.NotFound"))
    ec2.delete_vpc(VpcId=ghost_id)
    ghost_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:vpc/{ghost_id}"

    key = ctx.unique_name("sim2real-behav-part-")
    result = rgt.tag_resources(ResourceARNList=[live_arn, ghost_arn], Tags={key: "partial"})

    failed = result["FailedResourcesMap"]
    assert set(failed) == {ghost_arn}, (
        f"FailedResourcesMap named {sorted(failed)!r}, expected exactly the absent VPC "
        f"{ghost_arn!r} -- the live VPC {live_arn!r} must not fail and the absent one must not pass"
    )
    detail = failed[ghost_arn]
    assert detail["ErrorCode"] == "InvalidVpcID.NotFound", (
        f"the per-resource ErrorCode for an absent VPC was {detail['ErrorCode']!r}, "
        f"expected EC2's own InvalidVpcID.NotFound"
    )
    assert detail["StatusCode"] == 400, (
        f"the per-resource StatusCode was {detail['StatusCode']!r}, expected 400"
    )
    expected_message = f"The vpc ID '{ghost_id}' does not exist"
    assert detail["ErrorMessage"] == expected_message, (
        f"the per-resource ErrorMessage for an absent VPC was {detail['ErrorMessage']!r}, "
        f"expected {expected_message!r}"
    )

    described = _poll_until(
        lambda: ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [vpc_id]}])["Tags"],
        lambda tag_list: {t["Key"]: t["Value"] for t in tag_list}.get(key) == "partial",
        timeout_s=180.0,
    )
    tag_map = {t["Key"]: t["Value"] for t in described}
    assert tag_map.get(key) == "partial", (
        f"the live VPC {live_arn!r} never received {key}=partial (saw {tag_map!r}) -- a partial "
        f"failure must still apply the tags that succeeded"
    )


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
