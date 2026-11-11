"""catalog-ami-resolvable."""
# The AMI prerequisite every instance-launching member depends on: AWS's public SSM parameter for
# the latest Amazon Linux 2023 x86_64 AMI resolves to an available, Amazon-owned image. A dependent's
# launch failure is attributed here when this member fails. Read-only, AWS-owned data: nothing is
# created, so there is nothing to tear down.
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "catalog-ami-resolvable"
GROUP = "catalog"
SERVICES = ["ec2", "ssm"]

#: AWS-owned public parameter (contract/aws-owned: `/aws/service/*`).
AL2023_X86 = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_AMI_ID = re.compile(r"^ami-[0-9a-f]{8,17}$")


@tags("axis:happy-path", "cap:c5", "plane:control")
def run(ctx) -> None:
    """GetParameter on the AL2023 x86_64 public parameter yields an ami id that DescribeImages
    reports as one available, public, Amazon-owned x86_64 HVM EBS machine image."""
    ssm, ec2 = ctx.client("ssm"), ctx.client("ec2")

    try:
        param = ssm.get_parameter(Name=AL2023_X86)["Parameter"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            f"GetParameter {AL2023_X86}: the AWS-owned AMI parameter must resolve, got "
            f"{err.get('Code')!r}: {(err.get('Message') or '')[:120]!r}"
        ) from exc
    assert param.get("Name") == AL2023_X86, f"GetParameter Name: expected {AL2023_X86!r}, got {param.get('Name')!r}"
    assert param.get("Type") == "String", f"GetParameter Type: expected 'String', got {param.get('Type')!r}"
    ami = param.get("Value") or ""
    assert _AMI_ID.match(ami), f"GetParameter Value: expected an ami id (ami-<8..17 hex>), got {ami!r}"
    # The ARN's account field is not graded (AWS leaves it empty for an AWS-owned public parameter).
    partition = _partition(ctx)
    want_arn = re.compile(
        rf"^arn:{re.escape(partition)}:ssm:{re.escape(ctx.region)}:[0-9]*:parameter{re.escape(AL2023_X86)}$"
    )
    assert want_arn.match(param.get("ARN") or ""), (
        f"GetParameter ARN: expected arn:{partition}:ssm:{ctx.region}:<account>:parameter{AL2023_X86}, "
        f"got {param.get('ARN')!r}"
    )

    images = ec2.describe_images(ImageIds=[ami]).get("Images", [])
    assert [i.get("ImageId") for i in images] == [ami], (
        f"DescribeImages(ImageIds=[resolved]): expected exactly that one image, got "
        f"{[i.get('ImageId') for i in images]!r}"
    )
    img = images[0]
    want = {
        "State": "available",
        "Architecture": "x86_64",
        "ImageType": "machine",
        "VirtualizationType": "hvm",
        "RootDeviceType": "ebs",
        "Public": True,
        "ImageOwnerAlias": "amazon",
    }
    got = {k: img.get(k) for k in want}
    assert got == want, f"resolved image attributes: expected {want!r}, got {got!r}"

    # Independent read through the owner-scoped catalog query.
    owned = ec2.describe_images(
        Owners=["amazon"], Filters=[{"Name": "image-id", "Values": [ami]}]
    ).get("Images", [])
    assert [i.get("ImageId") for i in owned] == [ami], (
        f"DescribeImages(Owners=[amazon], image-id filter): expected [{ami!r}], got "
        f"{[i.get('ImageId') for i in owned]!r}"
    )


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN — never a literal 'aws'."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
