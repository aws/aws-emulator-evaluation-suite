"""image-ancestry-malformed-id-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "image-ancestry-malformed-id-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetImageAncestry succeeds for the latest Amazon AL2023 AMI and fails InvalidAMIID.Malformed
    with "The image ID 'not-a-valid-ami-id' is malformed" for that malformed id.
    """
    ec2 = ctx.client("ec2")

    real_image_id = _latest_amazon_ami(ec2)
    ec2.get_image_ancestry(ImageId=real_image_id)

    code, message = _error(lambda: ec2.get_image_ancestry(ImageId="not-a-valid-ami-id"))
    assert code == "InvalidAMIID.Malformed", f"expected InvalidAMIID.Malformed, got {code}"
    assert message == "The image ID 'not-a-valid-ami-id' is malformed", message


def _latest_amazon_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    assert images, "no Amazon-owned AMIs found to test against"
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected get_image_ancestry to be rejected, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
