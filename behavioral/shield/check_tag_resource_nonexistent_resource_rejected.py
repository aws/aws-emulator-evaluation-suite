"""tag-resource-nonexistent-resource-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-nonexistent-resource-rejected"
GROUP = "overly-permissive"
SERVICES = ["shield"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a well-formed but nonexistent Shield protection ARN and an S3 bucket ARN with the
    same InvalidResourceException "The referenced resource is invalid.", and ListTagsForResource rejects the
    nonexistent ARN the same way.
    """
    shield = ctx.client("shield")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    nonexistent_protection_arn = f"arn:aws:shield::{account_id}:protection/00000000-0000-0000-0000-000000000000"
    not_found_code, not_found_message = _error_code(
        lambda: shield.tag_resource(
            ResourceARN=nonexistent_protection_arn, Tags=[{"Key": "sim2real", "Value": "x"}]
        )
    )
    assert not_found_code == "InvalidResourceException", (
        f"expected InvalidResourceException, got {not_found_code!r}"
    )
    assert not_found_message == "The referenced resource is invalid.", f"unexpected message {not_found_message!r}"

    untaggable_arn = f"arn:aws:s3:::sim2real-shield-not-a-shield-resource-{account_id}"
    invalid_resource_code, invalid_resource_message = _error_code(
        lambda: shield.tag_resource(ResourceARN=untaggable_arn, Tags=[{"Key": "sim2real", "Value": "x"}])
    )
    assert invalid_resource_code == "InvalidResourceException", (
        f"expected InvalidResourceException, got {invalid_resource_code!r}"
    )
    assert invalid_resource_message == "The referenced resource is invalid.", (
        f"unexpected message {invalid_resource_message!r}"
    )

    # Cross-operation consistency: the same nonexistent ARN is rejected the same way by a
    # completely different read-only operation, confirming this is shared resource-resolution
    # behavior rather than a TagResource-specific quirk.
    list_tags_code, list_tags_message = _error_code(
        lambda: shield.list_tags_for_resource(ResourceARN=nonexistent_protection_arn)
    )
    assert list_tags_code == "InvalidResourceException", (
        f"expected InvalidResourceException from ListTagsForResource too, got {list_tags_code!r}"
    )
    assert list_tags_message == "The referenced resource is invalid.", f"unexpected message {list_tags_message!r}"


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
