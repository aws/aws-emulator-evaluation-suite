"""tag-resources-live-internet-gateway-and-nonexistent-one-partial-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resources-live-internet-gateway-and-nonexistent-one-partial-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2", "resourcegroupstaggingapi"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResources over one live internet gateway and one well-formed but nonexistent
    internet gateway ARN tags the live gateway and lists only the absent one in
    FailedResourcesMap, rather than rejecting the whole batch."""
    ec2 = ctx.client("ec2")
    rgt = ctx.client("resourcegroupstaggingapi")

    tag_key = ctx.unique_name("sim2real-behav-part-")

    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    live_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:internet-gateway/{igw_id}"
    ctx.on_cleanup(_delete_igw(ec2, igw_id))

    ghost_arn = f"arn:aws:ec2:{ctx.region}:{ctx.account}:internet-gateway/igw-{uuid.uuid4().hex[:17]}"

    result = rgt.tag_resources(ResourceARNList=[live_arn, ghost_arn], Tags={tag_key: "partial"})

    failed = result["FailedResourcesMap"]
    assert set(failed) == {ghost_arn}, (
        f"FailedResourcesMap named {sorted(failed)!r}, expected exactly the absent gateway "
        f"{ghost_arn!r} -- the live gateway {live_arn!r} must not fail and the absent one must not pass"
    )
    assert failed[ghost_arn]["StatusCode"] == 400, (
        f"expected a 400 status for the absent gateway, got {failed[ghost_arn]['StatusCode']!r}"
    )

    # Positive control: the live gateway really was tagged, not merely absent from the failure map.
    native_tags = {
        t["Key"]: t["Value"]
        for t in ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [igw_id]}])["Tags"]
    }
    assert native_tags.get(tag_key) == "partial", (
        f"expected the live gateway to carry {tag_key}='partial', got {native_tags!r}"
    )


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
