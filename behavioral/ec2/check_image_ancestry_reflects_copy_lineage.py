"""image-ancestry-reflects-copy-lineage."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "image-ancestry-reflects-copy-lineage"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After CopyImage, GetImageAncestry reports the source AMI as an ancestor across multiple copy hops."""
    ec2 = ctx.client("ec2")
    source_ami = _latest_amazon_linux_ami(ec2)

    copy1_name = ctx.unique_name("sim2real-ancestry-copy1-")
    copy1_id = ec2.copy_image(
        SourceImageId=source_ami,
        SourceRegion=ctx.region,
        Name=copy1_name,
        TagSpecifications=[
            {"ResourceType": "image", "Tags": [{"Key": "Name", "Value": copy1_name}]},
            {"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": copy1_name}]},
        ],
    )["ImageId"]
    ctx.on_cleanup(lambda: _deregister_and_clean_snapshots(ec2, copy1_id))
    _wait_image_available(ec2, copy1_id, timeout_s=1500.0, interval_s=20.0)

    ancestry1 = ec2.get_image_ancestry(ImageId=copy1_id)["ImageAncestryEntries"]
    matches1 = [e for e in ancestry1 if e.get("ImageId") == copy1_id]
    assert matches1, f"GetImageAncestry({copy1_id}) has no entry for the image itself: {ancestry1}"
    assert matches1[0]["SourceImageId"] == source_ami, (
        f"expected the first-generation copy's ancestor to be {source_ami!r}, "
        f"got {matches1[0].get('SourceImageId')!r}"
    )

    copy2_name = ctx.unique_name("sim2real-ancestry-copy2-")
    copy2_id = ec2.copy_image(
        SourceImageId=copy1_id,
        SourceRegion=ctx.region,
        Name=copy2_name,
        TagSpecifications=[
            {"ResourceType": "image", "Tags": [{"Key": "Name", "Value": copy2_name}]},
            {"ResourceType": "snapshot", "Tags": [{"Key": "Name", "Value": copy2_name}]},
        ],
    )["ImageId"]
    ctx.on_cleanup(lambda: _deregister_and_clean_snapshots(ec2, copy2_id))
    _wait_image_available(ec2, copy2_id, timeout_s=1500.0, interval_s=20.0)

    ancestry2 = ec2.get_image_ancestry(ImageId=copy2_id)["ImageAncestryEntries"]
    matches2 = [e for e in ancestry2 if e.get("ImageId") == copy2_id]
    assert matches2, f"GetImageAncestry({copy2_id}) has no entry for the image itself: {ancestry2}"
    assert matches2[0]["SourceImageId"] == copy1_id, (
        f"expected the second-generation copy's immediate ancestor to be {copy1_id!r}, "
        f"got {matches2[0].get('SourceImageId')!r}"
    )

    referenced_ids = {e.get("ImageId") for e in ancestry2} | {e.get("SourceImageId") for e in ancestry2}
    assert source_ami in referenced_ids, (
        f"the original source AMI {source_ami!r} is missing from the second-generation copy's "
        f"chained ancestry: {ancestry2}"
    )


def _latest_amazon_linux_ami(ec2) -> str:
    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
            {"Name": "root-device-type", "Values": ["ebs"]},
            {"Name": "virtualization-type", "Values": ["hvm"]},
        ],
    )
    images = resp["Images"]
    assert images, "no al2023-ami-*-x86_64 AMI found owned by amazon in this region"
    images.sort(key=lambda img: img["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _wait_image_available(ec2, image_id, *, timeout_s: float, interval_s: float) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        images = ec2.describe_images(ImageIds=[image_id])["Images"]
        if images and images[0]["State"] == "available":
            return
        if images and images[0]["State"] == "failed":
            raise AssertionError(f"image {image_id} copy failed: {images[0]}")
        time.sleep(interval_s)
    raise AssertionError(f"image {image_id} never reached 'available' within {timeout_s}s")


def _deregister_and_clean_snapshots(ec2, image_id) -> None:
    try:
        images = ec2.describe_images(ImageIds=[image_id])["Images"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidAMIID.NotFound":
            raise
        return
    snapshot_ids = []
    if images:
        for mapping in images[0].get("BlockDeviceMappings", []):
            ebs = mapping.get("Ebs")
            if ebs and ebs.get("SnapshotId"):
                snapshot_ids.append(ebs["SnapshotId"])
        ec2.deregister_image(ImageId=image_id)
    for snapshot_id in snapshot_ids:
        try:
            ec2.delete_snapshot(SnapshotId=snapshot_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidSnapshot.NotFound":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
