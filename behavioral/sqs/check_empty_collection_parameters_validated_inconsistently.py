"""empty-collection-parameters-validated-inconsistently."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "empty-collection-parameters-validated-inconsistently"
GROUP = "errors"
SERVICES = ["sqs"]

_TAGS = {"sim2real": "empty-collection-parameters-validated-inconsistently"}


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Empty Attributes/Tags/TagKeys on SetQueueAttributes, TagQueue and UntagQueue are refused with
    MissingParameter naming the parameter and change nothing, while CreateQueue with empty
    Attributes and GetQueueAttributes with empty AttributeNames succeed as no-ops.
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-emptycoll-"),
        Attributes={"VisibilityTimeout": "37"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    code, msg = _err(lambda: sqs.set_queue_attributes(QueueUrl=url, Attributes={}))
    assert code == "MissingParameter", f"SetQueueAttributes({{}}) gave code {code!r}"
    assert msg == "The request must contain the parameter Attribute.Name.", (
        f"SetQueueAttributes({{}}) gave message {msg!r}"
    )
    vt = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]
    assert vt["VisibilityTimeout"] == "37", (
        f"a refused empty SetQueueAttributes changed VisibilityTimeout to {vt['VisibilityTimeout']!r}"
    )

    code, msg = _err(lambda: sqs.tag_queue(QueueUrl=url, Tags={}))
    assert code == "MissingParameter", f"TagQueue({{}}) gave code {code!r}"
    assert msg == "The request must contain the parameter Tags.", f"TagQueue({{}}) gave message {msg!r}"
    tags_after = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
    assert tags_after == _TAGS, f"a refused empty TagQueue changed the tag set to {tags_after!r}"

    code, msg = _err(lambda: sqs.untag_queue(QueueUrl=url, TagKeys=[]))
    assert code == "MissingParameter", f"UntagQueue([]) gave code {code!r}"
    assert msg == "The request must contain the parameter TagKeys.", f"UntagQueue([]) gave message {msg!r}"
    tags_after = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
    assert tags_after == _TAGS, f"a refused empty UntagQueue changed the tag set to {tags_after!r}"

    name = ctx.unique_name("sim2real-behav-emptycreate-")
    created = sqs.create_queue(QueueName=name, Attributes={}, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=created))
    default_vt = sqs.get_queue_attributes(
        QueueUrl=created, AttributeNames=["VisibilityTimeout"])["Attributes"]["VisibilityTimeout"]
    assert default_vt == "30", (
        f"CreateQueue(Attributes={{}}) must take every attribute's default; "
        f"VisibilityTimeout read back as {default_vt!r}, expected the documented default '30'"
    )

    empty_read = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=[])
    assert "Attributes" not in empty_read, (
        f"GetQueueAttributes(AttributeNames=[]) returned Attributes "
        f"{empty_read.get('Attributes')!r}, expected no Attributes key at all"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
