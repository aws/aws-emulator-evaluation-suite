"""set-queue-attributes-one-invalid-value-applies-none-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-queue-attributes-one-invalid-value-applies-none-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

_TAGS = {"sim2real": "set-queue-attributes-one-invalid-value-applies-none-rejected"}
_NAMES = ["VisibilityTimeout", "DelaySeconds", "MessageRetentionPeriod"]


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _read(sqs, url):
    return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=_NAMES)["Attributes"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetQueueAttributes with two valid values and one out-of-range value is refused whole with
    InvalidAttributeValue naming the bad attribute and applies none; the corrected call applies
    all."""
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-sqa-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    before = _read(sqs, url)
    assert before == {"VisibilityTimeout": "30", "DelaySeconds": "0",
                      "MessageRetentionPeriod": "345600"}, (
        f"a fresh queue does not carry the documented defaults: {before!r}"
    )

    code, msg = _err(lambda: sqs.set_queue_attributes(QueueUrl=url, Attributes={
        "VisibilityTimeout": "45", "DelaySeconds": "5", "MessageRetentionPeriod": "10"}))
    assert code == "InvalidAttributeValue", f"the mixed request gave code {code!r}"
    assert msg == "Invalid value for the parameter MessageRetentionPeriod.", (
        f"the mixed request gave message {msg!r}"
    )
    after = _read(sqs, url)
    assert after == before, (
        f"a refused SetQueueAttributes applied some of its values: before {before!r}, "
        f"after {after!r}"
    )

    sqs.set_queue_attributes(QueueUrl=url, Attributes={
        "VisibilityTimeout": "45", "DelaySeconds": "5", "MessageRetentionPeriod": "120"})
    fixed = _read(sqs, url)
    assert fixed == {"VisibilityTimeout": "45", "DelaySeconds": "5",
                     "MessageRetentionPeriod": "120"}, (
        f"positive control: the corrected request did not apply all three values: {fixed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
