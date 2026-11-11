"""queue-attribute-range-bounds-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-attribute-range-bounds-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

_TAGS = {"sim2real": "queue-attribute-range-bounds-rejected"}
# (attribute, refused values, accepted boundary values). Documented ranges: retention 60..1209600
# seconds, maximum message size 1024..1048576 bytes, long-poll wait 0..20 seconds.
# KmsDataKeyReusePeriodSeconds is absent: a queue without a KMS key omits it from
# GetQueueAttributes, so its "unchanged after refusal" half needs an SSE-KMS queue.
_BOUNDS = [
    ("MessageRetentionPeriod", ("59", "1209601"), ("60", "1209600")),
    ("MaximumMessageSize", ("1023", "1048577"), ("1024", "1048576")),
    ("ReceiveMessageWaitTimeSeconds", ("21",), ("0", "20")),
]


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _get(sqs, url, name):
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=[name])["Attributes"].get(name)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetQueueAttributes refuses one step outside the documented ranges of MessageRetentionPeriod,
    MaximumMessageSize and ReceiveMessageWaitTimeSeconds with InvalidAttributeValue and its exact
    message, leaving the stored value unchanged, and accepts and reads back each inclusive boundary."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-arb-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    for name, refused, accepted in _BOUNDS:
        before = _get(sqs, url, name)
        assert before is not None, f"a fresh queue does not report {name}"
        for bad in refused:
            code, msg = _err(lambda n=name, v=bad: sqs.set_queue_attributes(
                QueueUrl=url, Attributes={n: v}))
            assert code == "InvalidAttributeValue", f"{name}={bad} gave code {code!r}"
            assert msg == f"Invalid value for the parameter {name}.", (
                f"{name}={bad} gave message {msg!r}"
            )
            now = _get(sqs, url, name)
            assert now == before, (
                f"the refused {name}={bad} changed the stored value from {before!r} to {now!r}"
            )
        for ok in accepted:
            sqs.set_queue_attributes(QueueUrl=url, Attributes={name: ok})
            now = _get(sqs, url, name)
            assert now == ok, f"boundary {name}={ok} was accepted but reads back as {now!r}"
            before = now


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
