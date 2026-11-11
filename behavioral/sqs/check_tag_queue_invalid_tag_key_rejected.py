"""tag-queue-invalid-tag-key-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-queue-invalid-tag-key-rejected"
GROUP = "error-semantics"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagQueue with a tag key that exceeds the 128-character AWS-wide tag-key limit is
    rejected rather than stored, distinct from the generic attribute-validation errors
    covered elsewhere; a normal tag key still persists."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-tagkey-"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    oversized_key = "k" * 300
    code, message = _error(lambda: sqs.tag_queue(QueueUrl=url, Tags={oversized_key: "v"}))
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue for a 300-char tag key, got {code!r}"
    expected_message = "Tag keys must be between 1 and 128 characters in length."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the oversized tag key was not stored
    tags_after = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
    assert oversized_key not in tags_after, f"oversized tag key was stored despite rejection: {tags_after!r}"

    # positive control: a normal tag key/value is accepted and persisted
    sqs.tag_queue(QueueUrl=url, Tags={"Environment": "sim2real-test"})
    ctx.on_cleanup(lambda: _try(lambda: sqs.untag_queue(QueueUrl=url, TagKeys=["Environment"])))
    control_tags = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
    assert control_tags.get("Environment") == "sim2real-test", f"expected control tag to persist, got {control_tags!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _try(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
