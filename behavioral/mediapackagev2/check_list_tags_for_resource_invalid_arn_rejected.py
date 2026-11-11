"""list-tags-for-resource-invalid-arn-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-resource-invalid-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]


BAD_ARN = "Invalid input resource arn: bad syntax"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e
    raise AssertionError(f"expected rejection but call SUCCEEDED, returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource with a malformed, non-ARN ResourceArn fails BadRequestException with the exact
    message rather than returning tags, while the ARN of a freshly tagged channel group returns its tag."""
    mp = ctx.client("mediapackagev2")
    group = ctx.unique_name("sim2real-mpkg-cg-")
    created = mp.create_channel_group(ChannelGroupName=group, Tags={"purpose": "behavioral"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))

    err = _client_error(lambda: mp.list_tags_for_resource(ResourceArn="not-an-arn-at-all"))
    code = err.response["Error"]["Code"]
    assert code == "BadRequestException", f"expected BadRequestException, got {code}"
    message = err.response["Error"]["Message"]
    assert message == BAD_ARN, f"expected message {BAD_ARN!r}, got {message!r}"

    # Positive control: the real ARN resolves and returns the tags set at creation.
    tags = mp.list_tags_for_resource(ResourceArn=created["Arn"])["Tags"]
    assert tags["purpose"] == "behavioral"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
