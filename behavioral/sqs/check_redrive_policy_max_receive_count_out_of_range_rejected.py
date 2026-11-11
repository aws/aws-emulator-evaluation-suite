"""redrive-policy-max-receive-count-out-of-range-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-policy-max-receive-count-out-of-range-rejected"
GROUP = 'dlq'
SERVICES = ['sqs']

_TAGS = {"sim2real": "redrive-policy-max-receive-count-out-of-range-rejected"}


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _redrive(sqs, url):
    return sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["RedrivePolicy"]).get("Attributes", {}).get("RedrivePolicy")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A RedrivePolicy with maxReceiveCount 0 or 1001 is refused with InvalidParameterValue and the
    exact range message, storing nothing; the boundary 1000 is accepted, read back, and links the
    source to the DLQ."""
    sqs = ctx.client("sqs")
    base = ctx.unique_name("sim2real-behav-mrc-")
    dlq_url = sqs.create_queue(QueueName=base + "-dlq", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(
        QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    src_url = sqs.create_queue(QueueName=base + "-src", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))

    for bad in (0, 1001):
        doc = json.dumps({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": bad})
        code, msg = _err(lambda d=doc: sqs.set_queue_attributes(
            QueueUrl=src_url, Attributes={"RedrivePolicy": d}))
        assert code == "InvalidParameterValue", f"maxReceiveCount={bad} gave code {code!r}"
        expected = (f"Value {doc} for parameter RedrivePolicy is invalid. Reason: Invalid value "
                    f"for maxReceiveCount: {bad}, valid values are from 1 to 1000 both inclusive.")
        assert msg == expected, f"maxReceiveCount={bad} gave message {msg!r}"
        stored = _redrive(sqs, src_url)
        assert stored is None, (
            f"the refused maxReceiveCount={bad} policy was stored anyway: {stored!r}"
        )

    sqs.set_queue_attributes(QueueUrl=src_url, Attributes={"RedrivePolicy": json.dumps(
        {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1000})})
    stored = _redrive(sqs, src_url)
    assert stored is not None, "the in-range maxReceiveCount=1000 policy was not stored"
    parsed = json.loads(stored)
    assert parsed.get("maxReceiveCount") == 1000, (
        f"the stored policy reads maxReceiveCount={parsed.get('maxReceiveCount')!r}, expected 1000"
    )
    assert parsed.get("deadLetterTargetArn") == dlq_arn, (
        "the stored policy does not name the DLQ it was given"
    )
    # ListDeadLetterSourceQueues is eventually consistent; it can lag the policy by ~40 s.
    deadline = time.monotonic() + 90
    while True:
        sources = sqs.list_dead_letter_source_queues(QueueUrl=dlq_url).get("queueUrls", [])
        if sources or time.monotonic() > deadline:
            break
        time.sleep(2)
    assert sources == [src_url], (
        f"after the accepted policy the DLQ lists {len(sources)} source queues, expected exactly "
        f"the one source"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
