"""tag-resources-and-untag-resources-round-trip-through-ec2-native-tags."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "tag-resources-and-untag-resources-round-trip-through-ec2-native-tags"
GROUP = "tagging-discovery"
SERVICES = ["ec2", "resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag TagResources applies to an EC2 VPC is readable through EC2's own DescribeTags, and
    UntagResources removes only that key -- a tag EC2's own CreateTags set on the same VPC
    survives, and both the native read and GetResources stop reporting the removed key.
    """
    ec2 = ctx.client("ec2")
    rgt = ctx.client("resourcegroupstaggingapi")

    control_key = ctx.unique_name("sim2real-behav-ctl-")
    control_value = ctx.unique_name("sim2real-behav-ctlv-")
    target_key = ctx.unique_name("sim2real-behav-tgt-")
    target_value = ctx.unique_name("sim2real-behav-tgtv-")

    vpc_id = ec2.create_vpc(CidrBlock="10.92.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    vpc_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:vpc/{vpc_id}"

    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": control_key, "Value": control_value}])

    failed = rgt.tag_resources(ResourceARNList=[vpc_arn], Tags={target_key: target_value})[
        "FailedResourcesMap"
    ]
    assert failed == {}, f"TagResources on the live vpc {vpc_arn!r} reported failures {failed!r}"

    tagged = _poll_until(
        lambda: _native_tags(ec2, vpc_id),
        lambda m: m.get(target_key) == target_value,
        timeout_s=120.0,
    )
    assert tagged.get(target_key) == target_value, (
        f"after TagResources, DescribeTags on {vpc_id!r} returned {tagged!r}, missing "
        f"{target_key}={target_value!r}"
    )
    assert tagged.get(control_key) == control_value, (
        f"after TagResources, DescribeTags on {vpc_id!r} returned {tagged!r}, missing the "
        f"unrelated {control_key}={control_value!r} CreateTags had already set"
    )

    found = _poll_until(
        lambda: {
            m["ResourceARN"]
            for m in rgt.get_resources(TagFilters=[{"Key": target_key, "Values": [target_value]}])[
                "ResourceTagMappingList"
            ]
        },
        lambda arns: vpc_arn in arns,
        timeout_s=120.0,
    )
    assert vpc_arn in found, (
        f"GetResources({target_key}={target_value!r}) returned {sorted(found)!r}, missing "
        f"{vpc_arn!r} after TagResources wrote the tag through the tagging API"
    )

    untag_failed = rgt.untag_resources(ResourceARNList=[vpc_arn], TagKeys=[target_key])[
        "FailedResourcesMap"
    ]
    assert untag_failed == {}, (
        f"UntagResources on the live vpc {vpc_arn!r} reported failures {untag_failed!r}"
    )

    untagged = _poll_until(
        lambda: _native_tags(ec2, vpc_id), lambda m: target_key not in m, timeout_s=120.0
    )
    assert target_key not in untagged, (
        f"after UntagResources, DescribeTags on {vpc_id!r} still returned {target_key}="
        f"{untagged.get(target_key)!r}"
    )
    assert untagged.get(control_key) == control_value, (
        f"after UntagResources removed {target_key!r}, DescribeTags on {vpc_id!r} returned "
        f"{untagged!r}, losing the unrelated {control_key}={control_value!r} it must not touch"
    )

    gone = _poll_until(
        lambda: {
            m["ResourceARN"]
            for m in rgt.get_resources(TagFilters=[{"Key": target_key, "Values": [target_value]}])[
                "ResourceTagMappingList"
            ]
        },
        lambda arns: vpc_arn not in arns,
        timeout_s=120.0,
    )
    assert vpc_arn not in gone, (
        f"GetResources({target_key}={target_value!r}) still returned {sorted(gone)!r} including "
        f"{vpc_arn!r} after UntagResources removed the key"
    )
    still_found = {
        m["ResourceARN"]
        for m in rgt.get_resources(TagFilters=[{"Key": control_key, "Values": [control_value]}])[
            "ResourceTagMappingList"
        ]
    }
    assert vpc_arn in still_found, (
        f"GetResources({control_key}={control_value!r}) returned {sorted(still_found)!r}, "
        f"missing {vpc_arn!r} -- the unrelated native tag must still index the vpc"
    )


def _native_tags(ec2, resource_id: str) -> dict:
    return {
        t["Key"]: t["Value"]
        for t in ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [resource_id]}])[
            "Tags"
        ]
    }


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
