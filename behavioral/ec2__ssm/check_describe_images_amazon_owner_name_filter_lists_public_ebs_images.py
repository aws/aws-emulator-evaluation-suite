"""describe-images-amazon-owner-name-filter-lists-public-ebs-images."""

from __future__ import annotations

import re

from behavioral_harness import tags

CHECK = "describe-images-amazon-owner-name-filter-lists-public-ebs-images"
GROUP = "ami-catalog"
SERVICES = ["ec2", "ssm"]

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_NAME_PATTERN = "al2023-ami-2023.*-x86_64"
_NAME_RE = re.compile(r"^al2023-ami-2023\.\S+-x86_64$")
_AMI_ID = re.compile(r"^ami-[0-9a-f]{8,17}$")
_OWNER_ID = re.compile(r"^[0-9]{12}$")


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeImages for the amazon owner and an AL2023 x86_64 name lists matching images only.

    Each is public, available and EBS-backed; the public parameter's image id is among them.
    """
    ec2 = ctx.client("ec2")
    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert _AMI_ID.match(ami), f"{_AL2023_AMI_PARAM} must resolve to an ami id, got {ami!r}"

    filters = [
        {"Name": "name", "Values": [_NAME_PATTERN]},
        {"Name": "architecture", "Values": ["x86_64"]},
        {"Name": "state", "Values": ["available"]},
    ]
    images = ec2.describe_images(Owners=["amazon"], Filters=filters)["Images"]
    ids = [i["ImageId"] for i in images]
    assert ami in ids, f"the {_AL2023_AMI_PARAM} image {ami!r} must be listed, got {ids!r}"

    want = {
        "ImageOwnerAlias": "amazon",
        "Public": True,
        "RootDeviceType": "ebs",
        "Architecture": "x86_64",
        "State": "available",
        "ImageType": "machine",
    }
    for image in images:
        got = {k: image.get(k) for k in want}
        assert got == want, f"{image['ImageId']!r}: expected {want!r}, got {got!r}"
        assert _NAME_RE.match(image["Name"]), (
            f"{image['ImageId']!r} is named {image['Name']!r}, outside the filter {_NAME_PATTERN!r}"
        )
        assert _AMI_ID.match(image["ImageId"]), f"malformed ImageId {image['ImageId']!r}"
        assert _OWNER_ID.match(image["OwnerId"]), (
            f"{image['ImageId']!r} OwnerId {image['OwnerId']!r}"
        )
    assert len(set(ids)) == len(ids), f"each image is listed once, got {ids!r}"

    # Control: the same owner and name filtered on the other architecture matches nothing. A target
    # that ignores the architecture filter answers the non-empty x86_64 listing above instead.
    arm = ec2.describe_images(
        Owners=["amazon"],
        Filters=[filters[0], {"Name": "architecture", "Values": ["arm64"]}, filters[2]],
    )["Images"]
    assert arm == [], (
        f"an x86_64 name filtered on arm64 must match nothing, got {[i['ImageId'] for i in arm]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
