"""catalog-ami-arm64-parameter-resolves-to-an-arm64-image."""
# Read-only, AWS-owned data: nothing is created, so there is nothing to tear down.
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "catalog-ami-arm64-parameter-resolves-to-an-arm64-image"
GROUP = "catalog"
SERVICES = ["ec2", "ssm"]

#: AWS-owned public parameters (contract/aws-owned: `/aws/service/*`).
AL2023_ARM64 = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
AL2023_X86 = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_AMI_ID = re.compile(r"^ami-[0-9a-f]{8,17}$")


@tags("axis:happy-path", "cap:c5", "plane:control")
def run(ctx) -> None:
    """The AL2023 arm64 public parameter resolves to an available, public, Amazon-owned arm64 HVM
    EBS image, a different image from the x86_64 parameter's, so the architecture follows the
    parameter rather than one fixed catalog image."""
    ssm, ec2 = ctx.client("ssm"), ctx.client("ec2")

    arm = _resolve(ssm, AL2023_ARM64)
    x86 = _resolve(ssm, AL2023_X86)
    assert arm != x86, f"the arm64 and x86_64 parameters resolved to the same image id {arm!r}"

    images = ec2.describe_images(ImageIds=[arm, x86]).get("Images", [])
    by_id = {i.get("ImageId"): i for i in images}
    assert sorted(by_id) == sorted([arm, x86]), (
        f"DescribeImages(ImageIds=[arm64, x86_64]): expected exactly those two images, got {sorted(by_id)!r}"
    )
    keys = ("State", "Architecture", "ImageType", "VirtualizationType", "RootDeviceType", "Public",
            "ImageOwnerAlias")
    for ami, arch in ((arm, "arm64"), (x86, "x86_64")):
        want = {
            "State": "available",
            "Architecture": arch,
            "ImageType": "machine",
            "VirtualizationType": "hvm",
            "RootDeviceType": "ebs",
            "Public": True,
            "ImageOwnerAlias": "amazon",
        }
        got = {k: by_id[ami].get(k) for k in keys}
        assert got == want, f"image resolved from the {arch} parameter: expected {want!r}, got {got!r}"

    # Independent read through an architecture-filtered, owner-scoped catalog query.
    owned = ec2.describe_images(
        Owners=["amazon"],
        Filters=[{"Name": "image-id", "Values": [arm, x86]}, {"Name": "architecture", "Values": ["arm64"]}],
    ).get("Images", [])
    assert [i.get("ImageId") for i in owned] == [arm], (
        f"DescribeImages(Owners=[amazon], image-id in both, architecture=arm64): expected only the "
        f"arm64 image, got {[i.get('ImageId') for i in owned]!r}"
    )


def _resolve(ssm, name: str) -> str:
    """The ami id the public parameter ``name`` holds; a refusal or a non-ami value fails."""
    try:
        param = ssm.get_parameter(Name=name)["Parameter"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            f"GetParameter {name}: the AWS-owned AMI parameter must resolve, got "
            f"{err.get('Code')!r}: {(err.get('Message') or '')[:120]!r}"
        ) from exc
    assert (param.get("Name"), param.get("Type")) == (name, "String"), (
        f"GetParameter {name}: expected (Name, Type) ({name!r}, 'String'), got "
        f"{(param.get('Name'), param.get('Type'))!r}"
    )
    ami = param.get("Value") or ""
    assert _AMI_ID.match(ami), f"GetParameter {name} Value: expected an ami id, got {ami!r}"
    return ami


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
