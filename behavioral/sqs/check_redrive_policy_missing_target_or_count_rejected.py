"""redrive-policy-missing-target-or-count-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-policy-missing-target-or-count-rejected"
GROUP = 'dlq'
SERVICES = ['sqs']

_TAGS = {"sim2real": "redrive-policy-missing-target-or-count-rejected"}


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
    """A RedrivePolicy naming a nonexistent DLQ, or omitting maxReceiveCount, is refused with
    InvalidParameterValue and its exact message and stores nothing; the same policy naming the
    real DLQ with a count is accepted."""
    sqs = ctx.client("sqs")
    base = ctx.unique_name("sim2real-behav-rpv-")
    dlq_url = sqs.create_queue(QueueName=base + "-dlq", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(
        QueueUrl=dlq_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    src_url = sqs.create_queue(QueueName=base + "-src", tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))

    ghost_arn = dlq_arn.rsplit(":", 1)[0] + ":" + base + "-never-created"
    ghost = json.dumps({"deadLetterTargetArn": ghost_arn, "maxReceiveCount": 3})
    code, msg = _err(lambda: sqs.set_queue_attributes(
        QueueUrl=src_url, Attributes={"RedrivePolicy": ghost}))
    assert code == "InvalidParameterValue", f"a ghost DLQ target gave code {code!r}"
    assert msg == (f"Value {ghost} for parameter RedrivePolicy is invalid. Reason: Dead letter "
                   f"target does not exist."), f"a ghost DLQ target gave message {msg!r}"
    assert _redrive(sqs, src_url) is None, "the policy naming a ghost DLQ was stored anyway"

    no_count = json.dumps({"deadLetterTargetArn": dlq_arn})
    code, msg = _err(lambda: sqs.set_queue_attributes(
        QueueUrl=src_url, Attributes={"RedrivePolicy": no_count}))
    assert code == "InvalidParameterValue", f"a policy without maxReceiveCount gave code {code!r}"
    assert msg == (f"Value {no_count} for parameter RedrivePolicy is invalid. Reason: Redrive "
                   f"policy does not contain mandatory attribute: maxReceiveCount."), (
        f"a policy without maxReceiveCount gave message {msg!r}"
    )
    assert _redrive(sqs, src_url) is None, "the policy without maxReceiveCount was stored anyway"

    sqs.set_queue_attributes(QueueUrl=src_url, Attributes={"RedrivePolicy": json.dumps(
        {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 3})})
    stored = _redrive(sqs, src_url)
    assert stored is not None, "positive control: the valid redrive policy was not stored"
    parsed = json.loads(stored)
    assert (parsed.get("deadLetterTargetArn"), parsed.get("maxReceiveCount")) == (dlq_arn, 3), (
        f"positive control: the stored policy reads maxReceiveCount="
        f"{parsed.get('maxReceiveCount')!r} and a target that "
        f"{'matches' if parsed.get('deadLetterTargetArn') == dlq_arn else 'does not match'} the DLQ"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
