"""internet-gateway-tags-visible-through-get-resources-both-directions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "internet-gateway-tags-visible-through-get-resources-both-directions"
GROUP = "tagging-discovery"
SERVICES = ["ec2", "resourcegroupstaggingapi"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag written by EC2's own CreateTags on an internet gateway is found by tagging-API
    GetResources, and a tag written by tagging-API TagResources is read back by EC2's own
    DescribeTags on the same gateway."""
    ec2 = ctx.client("ec2")
    rgt = ctx.client("resourcegroupstaggingapi")

    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    igw_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:internet-gateway/{igw_id}"
    ctx.on_cleanup(_delete_igw(ec2, igw_id))

    native_key = ctx.unique_name("sim2real-behav-nk-")
    native_value = ctx.unique_name("sim2real-behav-nv-")
    rgt_key = ctx.unique_name("sim2real-behav-rk-")
    rgt_value = ctx.unique_name("sim2real-behav-rv-")

    # Direction 1: native write (EC2 CreateTags), cross-service read (the tagging index is
    # eventually consistent).
    ec2.create_tags(Resources=[igw_id], Tags=[{"Key": native_key, "Value": native_value}])
    found = _poll_until(
        lambda: rgt.get_resources(TagFilters=[{"Key": native_key, "Values": [native_value]}])[
            "ResourceTagMappingList"
        ],
        lambda mappings: len(mappings) == 1,
        timeout_s=120.0,
    )
    assert len(found) == 1, f"GetResources matched {len(found)} resources, expected exactly 1: {found!r}"
    assert found[0]["ResourceARN"] == igw_arn, (
        f"discovered ARN {found[0]['ResourceARN']!r} does not equal the gateway's own ARN {igw_arn!r}"
    )

    # Direction 2: cross-service write (TagResources), native read (EC2 DescribeTags).
    tagged = rgt.tag_resources(ResourceARNList=[igw_arn], Tags={rgt_key: rgt_value})
    assert tagged["FailedResourcesMap"] == {}, (
        f"TagResources on a live internet gateway reported per-resource failures: {tagged['FailedResourcesMap']!r}"
    )

    native_view = _poll_until(
        lambda: _native_tags(ec2, igw_id),
        lambda m: m.get(rgt_key) == rgt_value,
        timeout_s=120.0,
    )
    assert native_view.get(rgt_key) == rgt_value, (
        f"EC2's own DescribeTags reports {native_view!r}, missing {rgt_key}={rgt_value!r} after a "
        f"tagging-api TagResources write"
    )
    # The native key written via EC2's own CreateTags must still be present too.
    assert native_view.get(native_key) == native_value, (
        f"EC2's own DescribeTags lost the natively-written tag {native_key}={native_value!r}: {native_view!r}"
    )


def _native_tags(ec2, igw_id):
    tags_ = ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [igw_id]}])["Tags"]
    return {t["Key"]: t["Value"] for t in tags_}


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


def _delete_igw(ec2, igw_id: str):
    def run_delete() -> None:
        try:
            ec2.delete_internet_gateway(InternetGatewayId=igw_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInternetGatewayID.NotFound":
                raise

    return run_delete


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
