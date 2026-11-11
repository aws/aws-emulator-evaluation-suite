"""redrive-allow-policy-by-queue-rejects-unlisted-source."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-allow-policy-by-queue-rejects-unlisted-source"
GROUP = 'errors'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "redrive-allow-policy-by-queue"}

# SQS returns this same code and reason for denyAll; only the per-source decision differs.
ERR_INVALID_PARAM = "InvalidParameterValue"
DENY_MESSAGE = (
    "Value RedrivePolicy(maxReceiveCount=1, deadLetterTargetArn={dlq_arn}) for parameter "
    "RedrivePolicy is invalid. Reason: The value for the dead-letter queue's RedriveAllowPolicy "
    "attribute prevents you from completing this request."
)


def _err(fn):
    """Return (Error.Code, Error.Message) for the ClientError fn raises. A success raises: an
    implementation accepting input real AWS rejects is the strongest signal here."""
    try:
        result = fn()
    except ClientError as exc:
        e = exc.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _redrive(arn):
    return json.dumps({"deadLetterTargetArn": arn, "maxReceiveCount": 1})


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """A byQueue RedriveAllowPolicy is a per-source allowlist: an unlisted queue's RedrivePolicy is
    refused with InvalidParameterValue and not stored; the listed queue's is accepted and redrives.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
    """
    sqs = ctx.client("sqs")
    marker = f"bq-marker-{uuid.uuid4().hex[:8]}"

    # VisibilityTimeout=1 so the redrive in the allowed leg happens in seconds.
    url_allowed = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-allowed",
        Attributes={"VisibilityTimeout": "1"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_allowed))
    allowed_arn = sqs.get_queue_attributes(
        QueueUrl=url_allowed, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    url_unlisted = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-unlisted",
        Attributes={"VisibilityTimeout": "1"},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_unlisted))

    # sourceQueueArns must name an existing ARN, so the listed source is created first.
    url_dlq = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-dlq",
        Attributes={"RedriveAllowPolicy": json.dumps(
            {"redrivePermission": "byQueue", "sourceQueueArns": [allowed_arn]})},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_dlq))
    dlq_arn = sqs.get_queue_attributes(
        QueueUrl=url_dlq, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    stored = json.loads(sqs.get_queue_attributes(
        QueueUrl=url_dlq, AttributeNames=["All"],
    )["Attributes"].get("RedriveAllowPolicy", "{}"))
    assert stored.get("redrivePermission") == "byQueue", (
        f"the dead-letter queue is not byQueue-scoped, so nothing below tests an allowlist: "
        f"RedriveAllowPolicy={stored!r}"
    )
    assert stored.get("sourceQueueArns") == [allowed_arn], (
        f"the allowlist does not name exactly the queue this check treats as allowed: "
        f"sourceQueueArns={stored.get('sourceQueueArns')!r}, expected {[allowed_arn]!r}"
    )

    # --- break exactly one thing: the SOURCE is a queue that is not on the allowlist ---
    code, message = _err(lambda: sqs.set_queue_attributes(
        QueueUrl=url_unlisted, Attributes={"RedrivePolicy": _redrive(dlq_arn)}))
    assert code == ERR_INVALID_PARAM, (
        f"a queue absent from a byQueue allowlist must be refused with {ERR_INVALID_PARAM!r} when "
        f"it names that dead-letter queue, got {code!r}"
    )
    assert message == DENY_MESSAGE.format(dlq_arn=dlq_arn), (
        f"the refusal must be attributed to the dead-letter queue's RedriveAllowPolicy, got "
        f"{message!r}"
    )

    # --- effect absent -----------------------------------------------------------------
    unlisted_attrs = sqs.get_queue_attributes(
        QueueUrl=url_unlisted, AttributeNames=["All"])["Attributes"]
    assert "RedrivePolicy" not in unlisted_attrs, (
        f"the refused association was still stored on the unlisted source queue: "
        f"RedrivePolicy={unlisted_attrs.get('RedrivePolicy')!r}"
    )

    # --- control: the ALLOWLISTED source makes the identical call, and it works --------
    try:
        sqs.set_queue_attributes(
            QueueUrl=url_allowed, Attributes={"RedrivePolicy": _redrive(dlq_arn)})
    except ClientError as exc:
        raise AssertionError(
            f"the queue named in sourceQueueArns was refused too ({exc.response.get('Error')!r}) "
            f"-- byQueue was evaluated as a blanket deny rather than as an allowlist"
        ) from exc
    allowed_attrs = sqs.get_queue_attributes(
        QueueUrl=url_allowed, AttributeNames=["All"])["Attributes"]
    assert json.loads(allowed_attrs["RedrivePolicy"])["deadLetterTargetArn"] == dlq_arn, (
        f"the permitted association did not store the dead-letter queue arn: "
        f"RedrivePolicy={allowed_attrs.get('RedrivePolicy')!r}"
    )

    sqs.send_message(QueueUrl=url_allowed, MessageBody=marker)
    dlq_bodies: list[str] = []
    deadline = time.monotonic() + 120
    while not dlq_bodies and time.monotonic() < deadline:
        # Receiving from the source without deleting drives the receive count past
        # maxReceiveCount=1, which is what triggers the redrive.
        sqs.receive_message(QueueUrl=url_allowed, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for m in sqs.receive_message(
            QueueUrl=url_dlq, MaxNumberOfMessages=10, WaitTimeSeconds=1,
        ).get("Messages", []):
            dlq_bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url_dlq, ReceiptHandle=m["ReceiptHandle"])
    assert dlq_bodies == [marker], (
        f"the allowlisted association was stored but the dead-letter queue never received the "
        f"redriven message: got {dlq_bodies!r}, expected {[marker]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
