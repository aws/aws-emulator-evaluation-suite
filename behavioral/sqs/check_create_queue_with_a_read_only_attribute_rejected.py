"""create-queue-with-a-read-only-attribute-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-queue-with-a-read-only-attribute-rejected"
GROUP = "validation"
SERVICES = ["sqs"]

_GONE = "AWS.SimpleQueueService.NonExistentQueue"


def _refusal(fn, code: str):
    """Call fn, which AWS must refuse with code; return the ClientError.

    A success fails the check, and a different code fails it raised from AWS's own error.
    """
    try:
        result = fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] == code:
            return exc
        raise AssertionError(f"expected {code}, got {exc.response['Error']['Code']}") from exc
    raise AssertionError(f"expected {code}, but the call succeeded: {result!r}")


def _drop_queue_named(sqs, name: str):
    """A cleanup deleting the queue called name, if one exists; it covers a create AWS should refuse."""

    def undo() -> None:
        try:
            url = sqs.get_queue_url(QueueName=name)["QueueUrl"]
            sqs.delete_queue(QueueUrl=url)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != _GONE:
                raise

    return undo


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateQueue naming QueueArn, an attribute GetQueueAttributes returns but no caller sets, is
    refused and creates no queue; the same create without it succeeds and AWS mints the ARN.
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-cqro-")
    legal = {"VisibilityTimeout": "40"}
    ctx.on_cleanup(_drop_queue_named(sqs, name))
    own_arn = f"arn:aws:sqs:{ctx.region}:{ctx.account}:{name}"

    err = _refusal(
        lambda: sqs.create_queue(
            QueueName=name, Attributes={**legal, "QueueArn": own_arn}, tags={"sim2real": CHECK}
        ),
        "InvalidAttributeName",
    )
    message = err.response["Error"]["Message"]
    assert message == "Unknown Attribute QueueArn.", f"the refusal carried the message {message!r}"

    err = _refusal(lambda: sqs.get_queue_url(QueueName=name), _GONE)
    message = err.response["Error"]["Message"]
    assert message == "The specified queue does not exist.", f"the absent queue read {message!r}"

    url = sqs.create_queue(QueueName=name, Attributes=dict(legal), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(_drop_queue_named(sqs, name))
    got = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn", "VisibilityTimeout"])
    attrs = got["Attributes"]
    assert attrs.get("VisibilityTimeout") == "40", f"the accepted create reads {attrs!r}"
    assert attrs.get("QueueArn") == own_arn, (
        f"the accepted queue reads a QueueArn of {len(attrs.get('QueueArn', ''))} characters, not its own ARN"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
