"""redrive-policy-dlq-type-mismatch-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-policy-dlq-type-mismatch-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

# SetQueueAttributes refuses a cross-type pairing with a message echoing the policy verbatim.
ERR_INVALID_PARAM = "InvalidParameterValue"
# Exact message, so an InvalidParameterValue for an unrelated reason cannot pass. The doubled
# period is what AWS returns.
MISMATCH_MESSAGE = (
    "Value {policy} for parameter RedrivePolicy is invalid. "
    "Reason: Dead-letter queue must be same type of queue as the source.."
)



def _err(fn):
    """Return (Error.Code, Error.Message) for the ClientError fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _redrive(arn):
    return json.dumps({"deadLetterTargetArn": arn, "maxReceiveCount": 3})


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A RedrivePolicy pairing a standard queue with a FIFO DLQ, or the reverse, is refused with
    InvalidParameterValue and not stored, while same-type pairings are accepted and read back."""
    sqs = ctx.client("sqs")

    std_src = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-") + "-std-src")[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=std_src))
    std_dlq = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-") + "-std-dlq")[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=std_dlq))
    fifo_src = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-src.fifo",
        Attributes={"FifoQueue": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=fifo_src))
    fifo_dlq = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-dlq.fifo",
        Attributes={"FifoQueue": "true"},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=fifo_dlq))

    def arn_of(url):
        return sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
            "QueueArn"
        ]

    std_dlq_arn, fifo_dlq_arn = arn_of(std_dlq), arn_of(fifo_dlq)
    assert fifo_dlq_arn.endswith(".fifo"), f"FIFO DLQ arn looks wrong: {fifo_dlq_arn}"
    assert not std_dlq_arn.endswith(".fifo"), f"standard DLQ arn looks wrong: {std_dlq_arn}"

    def redrive_policy(url):
        # SQS omits the Attributes key entirely when none of the requested attributes is set.
        return (
            sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["RedrivePolicy"])
            .get("Attributes", {})
            .get("RedrivePolicy")
        )

    # Both directions: an implementation may reject one mismatch and miss the other.
    for label, src_url, dlq_arn in (
        ("standard source -> FIFO DLQ", std_src, fifo_dlq_arn),
        ("FIFO source -> standard DLQ", fifo_src, std_dlq_arn),
    ):
        assert redrive_policy(src_url) is None, f"{label}: source already had a RedrivePolicy"
        code, message = _err(
            lambda: sqs.set_queue_attributes(
                QueueUrl=src_url, Attributes={"RedrivePolicy": _redrive(dlq_arn)}
            )
        )
        assert code == ERR_INVALID_PARAM, (
            f"{label}: expected {ERR_INVALID_PARAM}, got {code!r} ({message!r})"
        )
        assert message == MISMATCH_MESSAGE.format(policy=_redrive(dlq_arn)), (
            f"{label}: the refusal must name the queue-type rule, got {message!r}"
        )
        # effect absent: nothing was stored, not even partially
        stored = redrive_policy(src_url)
        assert stored is None, (
            f"{label}: the rejected RedrivePolicy was stored anyway: {stored}"
        )

    # --- control: same-type pairings are accepted and read back exactly ----------------
    for label, src_url, dlq_arn in (
        ("standard source -> standard DLQ", std_src, std_dlq_arn),
        ("FIFO source -> FIFO DLQ", fifo_src, fifo_dlq_arn),
    ):
        sqs.set_queue_attributes(
            QueueUrl=src_url, Attributes={"RedrivePolicy": _redrive(dlq_arn)}
        )
        stored = redrive_policy(src_url)
        assert stored, f"{label}: valid RedrivePolicy was not stored"
        parsed = json.loads(stored)
        assert parsed.get("deadLetterTargetArn") == dlq_arn, (
            f"{label}: stored deadLetterTargetArn {parsed.get('deadLetterTargetArn')!r} "
            f"!= {dlq_arn!r}"
        )
        assert int(parsed.get("maxReceiveCount")) == 3, (
            f"{label}: stored maxReceiveCount {parsed.get('maxReceiveCount')!r} != 3"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
