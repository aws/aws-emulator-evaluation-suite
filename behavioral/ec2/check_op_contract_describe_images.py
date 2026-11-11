"""op-contract-describe-images."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-images"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeImages returns real, well-formed AMI records for a known public owner and
    rejects a fabricated, malformed AMI ID with InvalidAMIID.Malformed."""
    ec2 = ctx.client("ec2")

    resp = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )
    images = resp.get("Images", [])
    if not images:
        raise AssertionError("no amazon-owned al2023 AMI visible in this account/region")
    image = images[0]
    assert image["State"] == "available"
    assert image["ImageId"].startswith("ami-")
    assert image["OwnerId"]
    assert image["Public"] is True

    by_id = ec2.describe_images(ImageIds=[image["ImageId"]])["Images"]
    assert len(by_id) == 1 and by_id[0]["ImageId"] == image["ImageId"]

    # Error boundary: a fabricated AMI ID with an all-zero body is rejected as malformed
    # (AWS applies additional structural checks to the 17-hex-character ID body beyond
    # matching the plain "ami-" + hex-chars shape).
    code, message = _error_of(lambda: ec2.describe_images(ImageIds=["ami-0000000000000000f"]))
    assert code == "InvalidAMIID.Malformed", f"expected InvalidAMIID.Malformed, got {code}"
    assert message == 'Invalid id: "ami-0000000000000000f"', message


def _error_of(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected rejection, but call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
