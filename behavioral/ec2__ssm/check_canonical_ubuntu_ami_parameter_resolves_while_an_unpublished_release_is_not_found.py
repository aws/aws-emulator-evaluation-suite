"""canonical-ubuntu-ami-parameter-resolves-while-an-unpublished-release-is-not-found."""

# Read-only, AWS-owned data: nothing is created, so there is nothing to tear down.
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "canonical-ubuntu-ami-parameter-resolves-while-an-unpublished-release-is-not-found"
GROUP = "catalog"
SERVICES = ["ec2", "ssm"]

#: AWS-owned public parameter (contract/aws-owned: `/aws/service/*`).
_PATH = "/aws/service/canonical/ubuntu/server"
UBUNTU_22_04 = f"{_PATH}/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
#: No Ubuntu release carries this version number; the path is otherwise well formed.
_UNPUBLISHED = f"{_PATH}/37.04/stable/current/amd64/hvm/ebs-gp2/ami-id"


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetParameter on the Ubuntu 22.04 amd64 ami-id parameter resolves to an available, public
    Canonical image DescribeImages reports; the same path for an unpublished release is
    ParameterNotFound."""
    ssm, ec2 = ctx.client("ssm"), ctx.client("ec2")

    param = ssm.get_parameter(Name=UBUNTU_22_04)["Parameter"]
    assert param.get("Name") == UBUNTU_22_04, (
        f"GetParameter Name: expected {UBUNTU_22_04!r}, got {param.get('Name')!r}"
    )
    assert param.get("Type") == "String", (
        f"GetParameter Type: expected 'String', got {param.get('Type')!r}"
    )
    ami = param.get("Value") or ""
    assert ami.startswith("ami-"), f"GetParameter Value: expected an ami id, got {ami!r}"

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
    }
    got = {k: img.get(k) for k in want}
    assert got == want, f"resolved image attributes: expected {want!r}, got {got!r}"
    name = img.get("Name") or ""
    description = img.get("Description") or ""
    assert name.startswith("ubuntu/images/"), (
        f"resolved image Name: expected an ubuntu/images/ name, got {name!r}"
    )
    assert "Canonical, Ubuntu, 22.04" in description, (
        f"resolved image Description: expected it to name 'Canonical, Ubuntu, 22.04', got {description!r}"
    )

    try:
        ssm.get_parameter(Name=_UNPUBLISHED)
        raise AssertionError(f"GetParameter {_UNPUBLISHED!r} unexpectedly succeeded")
    except ClientError as exc:
        err = exc.response.get("Error", {})
        assert (err.get("Code"), err.get("Message")) == ("ParameterNotFound", ""), (
            f"GetParameter {_UNPUBLISHED!r}: expected ('ParameterNotFound', ''), got "
            f"{(err.get('Code'), err.get('Message'))!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
