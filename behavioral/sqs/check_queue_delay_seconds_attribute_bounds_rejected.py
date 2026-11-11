"""queue-delay-seconds-attribute-bounds-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-delay-seconds-attribute-bounds-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

_TAGS = {"sim2real": "queue-delay-seconds-attribute-bounds-rejected"}
_MESSAGE = "Invalid value for the parameter DelaySeconds."


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _get(sqs, url):
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["DelaySeconds"])["Attributes"]["DelaySeconds"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetQueueAttributes refuses a DelaySeconds one step outside 0..900, or non-numeric, with
    InvalidAttributeValue and its exact message, leaving the stored value unchanged, and accepts both
    boundaries; CreateQueue with an out-of-range DelaySeconds is refused the same way and creates no queue."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-delaybounds-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    before = _get(sqs, url)
    assert before == "0", f"a fresh queue's DelaySeconds was {before!r}, expected the default '0'"

    for bad in ("-1", "901", "abc"):
        code, msg = _err(lambda v=bad: sqs.set_queue_attributes(
            QueueUrl=url, Attributes={"DelaySeconds": v}))
        assert code == "InvalidAttributeValue", f"DelaySeconds={bad} gave code {code!r}"
        assert msg == _MESSAGE, f"DelaySeconds={bad} gave message {msg!r}"
        now = _get(sqs, url)
        assert now == before, (
            f"the refused DelaySeconds={bad} changed the stored value from {before!r} to {now!r}"
        )

    for ok in ("0", "900"):
        sqs.set_queue_attributes(QueueUrl=url, Attributes={"DelaySeconds": ok})
        now = _get(sqs, url)
        assert now == ok, f"boundary DelaySeconds={ok} was accepted but reads back as {now!r}"
        before = now

    name = ctx.unique_name("sim2real-behav-delaycreate-")
    created = []

    def _cleanup_create():
        for u in created:
            sqs.delete_queue(QueueUrl=u)

    ctx.on_cleanup(_cleanup_create)

    def _create_bad():
        out = sqs.create_queue(QueueName=name, Attributes={"DelaySeconds": "901"}, tags=_TAGS)
        created.append(out["QueueUrl"])
        return out

    code, msg = _err(_create_bad)
    assert code == "InvalidAttributeValue", f"CreateQueue with DelaySeconds=901 gave code {code!r}"
    assert msg == _MESSAGE, f"CreateQueue with DelaySeconds=901 gave message {msg!r}"

    code, msg = _err(lambda: sqs.get_queue_url(QueueName=name))
    assert (code, msg) == ("AWS.SimpleQueueService.NonExistentQueue",
                           "The specified queue does not exist."), (
        f"the refused CreateQueue left a resolvable queue behind: GetQueueUrl gave {(code, msg)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
