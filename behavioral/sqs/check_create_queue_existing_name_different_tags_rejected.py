"""create-queue-existing-name-different-tags-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-queue-existing-name-different-tags-rejected"
GROUP = 'lifecycle'
SERVICES = ['sqs']

_TAGS = {"sim2real": "create-queue-existing-name-different-tags-rejected", "team": "alpha"}
# The real message ends in a trailing space.
MSG_TAGS = "A queue already exists with the same name and a different value for tags "


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-creating an existing queue with a different tag value is refused with QueueAlreadyExists
    and changes nothing; re-creating with identical tags returns the same URL.
    """
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-cqt-")
    attrs = {"VisibilityTimeout": "40"}
    url = sqs.create_queue(QueueName=name, Attributes=attrs, tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    changed = dict(_TAGS, team="beta")
    code, msg = _err(lambda: sqs.create_queue(QueueName=name, Attributes=attrs, tags=changed))
    assert code == "QueueAlreadyExists", f"a different tag value gave code {code!r}"
    assert msg == MSG_TAGS, f"a different tag value gave message {msg!r}"
    stored = sqs.list_queue_tags(QueueUrl=url).get("Tags", {})
    assert stored == _TAGS, f"the refused re-create changed the stored tags to {stored!r}"

    again = sqs.create_queue(QueueName=name, Attributes=attrs, tags=_TAGS)["QueueUrl"]
    assert again == url, f"an identical re-create returned a different URL: {again!r} != {url!r}"
    assert sqs.list_queue_tags(QueueUrl=url).get("Tags", {}) == _TAGS, (
        "the identical re-create changed the stored tags"
    )
    vt = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["VisibilityTimeout"])["Attributes"]["VisibilityTimeout"]
    assert vt == "40", f"the queue's VisibilityTimeout reads {vt!r} after the re-creates"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
