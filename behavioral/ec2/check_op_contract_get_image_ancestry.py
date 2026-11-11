"""op-contract-get-image-ancestry."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-get-image-ancestry"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetImageAncestry traces a real AMI's lineage; a well-formed but nonexistent
    AMI ID is rejected with the documented not-found code."""
    ec2 = ctx.client("ec2")

    image_id = _latest_amazon_ami(ec2)

    resp = ec2.get_image_ancestry(ImageId=image_id)
    entries = resp["ImageAncestryEntries"]
    assert isinstance(entries, list) and len(entries) >= 1, "expected at least one ancestry entry"
    # The chain starts with the AMI itself.
    assert entries[0]["ImageId"] == image_id, entries[0]

    # A hand-picked placeholder like "ami-0123456789abcdef0" is the right
    # length and passes the general AMI-ID shape check, so it isn't rejected
    # for being obviously fake. Deriving the probe ID from a real AMI ID
    # (just flipping its trailing hex digit) keeps the exact structure of a
    # genuine ID while being, for all practical purposes, guaranteed not to
    # exist. Confirmed against real AWS: a well-formed but absent id gets
    # the same InvalidAMIID.NotFound that DescribeImages uses, not a
    # Malformed rejection.
    fake_image_id = _mutate_id(image_id)
    code, message = _error(lambda: ec2.get_image_ancestry(ImageId=fake_image_id))
    assert code == "InvalidAMIID.NotFound", f"expected InvalidAMIID.NotFound, got {code}"
    assert message == f"The image id '[{fake_image_id}]' does not exist", message


def _mutate_id(real_id: str) -> str:
    prefix, _, hexpart = real_id.rpartition("-")
    last = hexpart[-1]
    new_last = "1" if last != "1" else "2"
    return f"{prefix}-{hexpart[:-1]}{new_last}"


def _latest_amazon_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["amzn2-ami-hvm-*-x86_64-gp2"]},
                {"Name": "state", "Values": ["available"]},
            ],
        )["Images"]
    assert images, "no Amazon-owned AMIs found to test against"
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call
    that succeeds raises AssertionError, because an emulator accepting what real AWS
    refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
