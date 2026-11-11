"""redrive-allow-policy-deny-all-rejects-dlq-association-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "redrive-allow-policy-deny-all-rejects-dlq-association-rejected"
GROUP = 'errors'
SERVICES = ['sqs']

_TAGS = {"sim2real:managed": "true", "sim2real": "redrive-allow-policy-deny-all"}

# SQS returns the query-style code "InvalidParameterValue" here, which the service model does not
# declare (it models InvalidAttributeValue instead).
ERR_INVALID_PARAM = "InvalidParameterValue"
# The exact message, so an InvalidParameterValue raised for an unrelated reason (a malformed ARN,
# a bad maxReceiveCount, a cross-type pairing) cannot satisfy the negative.
DENY_MESSAGE = (
    "Value RedrivePolicy(maxReceiveCount=1, deadLetterTargetArn={dlq_arn}) for parameter "
    "RedrivePolicy is invalid. Reason: The value for the dead-letter queue's RedriveAllowPolicy "
    "attribute prevents you from completing this request."
)


def _err(fn):
    """Return (Error.Code, Error.Message) for the ClientError fn raises; a success raises."""
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
    """Naming a denyAll RedriveAllowPolicy queue as a DLQ fails InvalidParameterValue and stores
    no RedrivePolicy; after flipping it to allowAll the same call succeeds and redrives a message.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SetQueueAttributes.html
    """
    sqs = ctx.client("sqs")
    marker = f"redrive-marker-{uuid.uuid4().hex[:8]}"

    url_dlq = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-dlq",
        Attributes={"RedriveAllowPolicy": json.dumps({"redrivePermission": "denyAll"})},
        tags=_TAGS,
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_dlq))
    dlq_arn = sqs.get_queue_attributes(
        QueueUrl=url_dlq, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]

    stored = json.loads(sqs.get_queue_attributes(
        QueueUrl=url_dlq, AttributeNames=["All"],
    )["Attributes"].get("RedriveAllowPolicy", "{}"))
    assert stored.get("redrivePermission") == "denyAll", (
        f"the dead-letter queue never carried denyAll, so the refusal below would prove nothing: "
        f"RedriveAllowPolicy={stored!r}"
    )

    # VisibilityTimeout=1 so the redrive in the control leg happens in seconds rather than minutes.
    url_src = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-") + "-src",
        Attributes={"VisibilityTimeout": "1"},
        tags=_TAGS,
    )["QueueUrl"]
    # Registered before the DLQ association exists, and LIFO puts it first: the source is deleted
    # before the DLQ, so no redrive can push a message into the DLQ while it is being torn down.
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url_src))

    # --- break exactly one thing: point the source at a denyAll dead-letter queue ------
    code, message = _err(lambda: sqs.set_queue_attributes(
        QueueUrl=url_src, Attributes={"RedrivePolicy": _redrive(dlq_arn)}))
    assert code == ERR_INVALID_PARAM, (
        f"naming a denyAll queue as a dead-letter target must be refused with "
        f"{ERR_INVALID_PARAM!r}, got {code!r}"
    )
    assert message == DENY_MESSAGE.format(dlq_arn=dlq_arn), (
        f"the refusal must be attributed to the dead-letter queue's RedriveAllowPolicy, got "
        f"{message!r}"
    )

    # --- effect absent: the refused association was not stored ------------------------
    attrs_after_denial = sqs.get_queue_attributes(
        QueueUrl=url_src, AttributeNames=["All"])["Attributes"]
    assert "RedrivePolicy" not in attrs_after_denial, (
        f"a refused association still stored a RedrivePolicy on the source queue: "
        f"RedrivePolicy={attrs_after_denial.get('RedrivePolicy')!r}"
    )

    # --- control: repair the one broken thing, and the identical call must succeed -----
    sqs.set_queue_attributes(
        QueueUrl=url_dlq,
        Attributes={"RedriveAllowPolicy": json.dumps({"redrivePermission": "allowAll"})},
    )
    # The allowAll change propagates eventually, so the identical call is retried within a bound.
    deadline = time.monotonic() + 90
    while True:
        try:
            sqs.set_queue_attributes(
                QueueUrl=url_src, Attributes={"RedrivePolicy": _redrive(dlq_arn)})
            break
        except ClientError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"flipping the dead-letter queue to allowAll did not permit the identical "
                    f"association: still {exc.response.get('Error')!r} -- the check cannot pass "
                    f"by refusing every association"
                ) from exc
            time.sleep(2)
    attrs_after_allow = sqs.get_queue_attributes(
        QueueUrl=url_src, AttributeNames=["All"])["Attributes"]
    assert json.loads(attrs_after_allow["RedrivePolicy"])["deadLetterTargetArn"] == dlq_arn, (
        f"the permitted association did not store the dead-letter queue arn: "
        f"RedrivePolicy={attrs_after_allow.get('RedrivePolicy')!r}"
    )

    # --- and the association it created is functional, not merely stored --------------
    sqs.send_message(QueueUrl=url_src, MessageBody=marker)
    dlq_bodies: list[str] = []
    deadline = time.monotonic() + 120
    while not dlq_bodies and time.monotonic() < deadline:
        # Receiving from the source without deleting is what drives the receive count past
        # maxReceiveCount=1 and triggers the redrive.
        sqs.receive_message(QueueUrl=url_src, MaxNumberOfMessages=10, WaitTimeSeconds=1)
        for m in sqs.receive_message(
            QueueUrl=url_dlq, MaxNumberOfMessages=10, WaitTimeSeconds=1,
        ).get("Messages", []):
            dlq_bodies.append(m["Body"])
            sqs.delete_message(QueueUrl=url_dlq, ReceiptHandle=m["ReceiptHandle"])
    assert dlq_bodies == [marker], (
        f"the association was stored but the dead-letter queue never received the redriven "
        f"message: got {dlq_bodies!r}, expected {[marker]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
