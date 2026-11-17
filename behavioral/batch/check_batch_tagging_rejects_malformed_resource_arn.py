"""batch-tagging-rejects-malformed-resource-arn."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags


def _error_code(fn: Callable[[], Any]):
    """Call fn(); return its botocore Error (code, message, request id). An unexpected SUCCESS
    raises, because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return (
            err.response["Error"]["Code"],
            err.response["Error"].get("Message"),
            err.response["ResponseMetadata"].get("RequestId"),
        )
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


CHECK = "batch-tagging-rejects-malformed-resource-arn"
GROUP = "tagging"
SERVICES = ["batch"]

_BAD_ARN = "not-an-arn"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource and UntagResource each reject a resourceArn that is not a valid
    Batch ARN with BadRequestException; the identical calls against a real scheduling policy
    ARN list and remove its tag."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-sp-")
    arn = batch.create_scheduling_policy(name=name, tags={"sim2real": "true"})["arn"]
    ctx.on_cleanup(lambda: batch.delete_scheduling_policy(arn=arn))

    list_code, list_message, _list_request_id = _error_code(
        lambda: batch.list_tags_for_resource(resourceArn=_BAD_ARN)
    )
    assert list_code == "BadRequestException", (
        f"expected BadRequestException from ListTagsForResource, got {list_code!r}"
    )
    expected_list_message = "Invalid input resource arn: bad syntax"
    assert list_message == expected_list_message, (
        f"expected message {expected_list_message!r}, got {list_message!r}"
    )

    untag_code, untag_message, _untag_request_id = _error_code(
        lambda: batch.untag_resource(resourceArn=_BAD_ARN, tagKeys=["sim2real"])
    )
    assert untag_code == "BadRequestException", (
        f"expected BadRequestException from UntagResource, got {untag_code!r}"
    )
    expected_untag_message = "Invalid input resource arn: bad syntax"
    assert untag_message == expected_untag_message, (
        f"expected message {expected_untag_message!r}, got {untag_message!r}"
    )

    # Positive control: the identical calls against the real scheduling policy's ARN work.
    tags_before = batch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_before == {"sim2real": "true"}, f"expected the tag set at creation, got {tags_before!r}"

    batch.untag_resource(resourceArn=arn, tagKeys=["sim2real"])
    tags_after = batch.list_tags_for_resource(resourceArn=arn)["tags"]
    assert tags_after == {}, f"expected the tag removed on an independent read, got {tags_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
