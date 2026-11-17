"""vpc-tags-visible-through-get-resources-both-directions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "vpc-tags-visible-through-get-resources-both-directions"
GROUP = "tagging-discovery"
SERVICES = ["ec2", "resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag EC2's own CreateTags writes on a VPC is found by tagging-API GetResources, a tag
    TagResources writes on the same VPC is read back by EC2's own DescribeTags, and UntagResources
    removes only the tag key it names.
    """
    ec2 = ctx.client("ec2")
    rgt = ctx.client("resourcegroupstaggingapi")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.80.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc",
                            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))
    vpc_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:vpc/{vpc_id}"

    native_key = ctx.unique_name("sim2real-behav-nk-")
    native_value = ctx.unique_name("sim2real-behav-nv-")
    rgt_key = ctx.unique_name("sim2real-behav-rk-")
    rgt_value = ctx.unique_name("sim2real-behav-rv-")

    # Direction 1: EC2's own CreateTags, then a cross-service read through GetResources.
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": native_key, "Value": native_value}])
    found = _poll_until(
        lambda: rgt.get_resources(
            TagFilters=[{"Key": native_key, "Values": [native_value]}]
        )["ResourceTagMappingList"],
        lambda mappings: len(mappings) == 1,
        timeout_s=120.0,
    )
    assert len(found) == 1, f"GetResources matched {len(found)} resources, expected exactly 1: {found!r}"
    assert found[0]["ResourceARN"] == vpc_arn, (
        f"discovered ARN {found[0]['ResourceARN']!r} does not equal the VPC's own ARN {vpc_arn!r}"
    )

    # Direction 2: tagging-API TagResources, then a native read through EC2's own DescribeTags.
    tagged = rgt.tag_resources(ResourceARNList=[vpc_arn], Tags={rgt_key: rgt_value})
    assert tagged["FailedResourcesMap"] == {}, (
        f"TagResources on a live VPC reported per-resource failures: {tagged['FailedResourcesMap']!r}"
    )

    def _native_tags():
        described = ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [vpc_id]}])["Tags"]
        return {t["Key"]: t["Value"] for t in described}

    after_tag = _poll_until(_native_tags, lambda m: m.get(rgt_key) == rgt_value, timeout_s=180.0)
    assert after_tag.get(rgt_key) == rgt_value, (
        f"EC2's own DescribeTags reports {after_tag!r}, missing {rgt_key}={rgt_value!r} "
        f"after a tagging-API TagResources write"
    )
    assert after_tag.get(native_key) == native_value, (
        f"EC2's own DescribeTags lost the natively-written tag {native_key}={native_value!r}: {after_tag!r}"
    )

    # UntagResources removes only the key it names; the natively-written tag survives.
    untagged = rgt.untag_resources(ResourceARNList=[vpc_arn], TagKeys=[rgt_key])
    assert untagged["FailedResourcesMap"] == {}, (
        f"UntagResources on a live VPC reported per-resource failures: {untagged['FailedResourcesMap']!r}"
    )

    after_untag = _poll_until(_native_tags, lambda m: rgt_key not in m, timeout_s=180.0)
    assert rgt_key not in after_untag, (
        f"EC2's own DescribeTags still reports {rgt_key!r} after UntagResources removed it: {after_untag!r}"
    )
    assert after_untag.get(native_key) == native_value, (
        f"UntagResources on {rgt_key!r} also removed the untouched tag {native_key!r}: {after_untag!r}"
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
