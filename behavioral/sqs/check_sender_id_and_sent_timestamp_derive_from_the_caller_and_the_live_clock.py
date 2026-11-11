"""sender-id-and-sent-timestamp-derive-from-the-caller-and-the-live-clock."""

from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "sender-id-and-sent-timestamp-derive-from-the-caller-and-the-live-clock"
GROUP = "invariants"
SERVICES = ["sqs"]

_SKEW_MS = 300_000  # allowance for client-vs-service clock skew
_POLL_S = 40.0

_TAGS = {
    "sim2real:managed": "true",
    "sim2real": "sender-id-derivation",
}


def _receive_one(sqs, url, *, body, timeout_s):
    """Poll until the message with exactly `body` arrives; raise on the deadline.

    Other messages are re-exposed with visibility 0 so a later poll need not wait them out.
    """
    deadline = time.monotonic() + timeout_s
    seen: list[str] = []
    while time.monotonic() < deadline:
        for msg in sqs.receive_message(
            QueueUrl=url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=2,
            MessageSystemAttributeNames=["All"],
        ).get("Messages", []):
            if msg["Body"] == body:
                return msg
            seen.append(msg["Body"])
            sqs.change_message_visibility(
                QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"], VisibilityTimeout=0
            )
    raise AssertionError(
        f"{body!r} was not delivered within {timeout_s}s; bodies seen instead: {seen!r}"
    )


def _system_attribute(msg, name):
    attrs = msg.get("Attributes") or {}
    assert name in attrs, (
        f"ReceiveMessage(MessageSystemAttributeNames=['All']) did not return {name}; SQS documents "
        f"it as a supported system attribute. Got {sorted(attrs)}"
    )
    return attrs[name]


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """SenderId equals the caller's sts UserId and SentTimestamp comes from the live clock.

    No replayed recording can carry either value, so both are checked against fresh ground truth.

    Reference: https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_ReceiveMessage.html
    Reference: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
    """
    sqs = ctx.client("sqs")
    caller = ctx.client("sts").get_caller_identity()
    user_id = caller["UserId"]
    account = caller["Account"]
    assert user_id, f"sts:GetCallerIdentity returned no UserId: keys {sorted(caller)}"

    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    token = uuid.uuid4().hex[:8]
    first_body = f"sender-first-{token}"
    second_body = f"sender-second-{token}"

    before_ms = int(time.time() * 1000)
    sqs.send_message(QueueUrl=url, MessageBody=first_body)
    sqs.send_message(QueueUrl=url, MessageBody=second_body)
    after_ms = int(time.time() * 1000)
    assert after_ms >= before_ms, "the runner's wall clock went backwards across the two sends"

    first = _receive_one(sqs, url, body=first_body, timeout_s=_POLL_S)
    second = _receive_one(sqs, url, body=second_body, timeout_s=_POLL_S)

    first_sender = _system_attribute(first, "SenderId")
    second_sender = _system_attribute(second, "SenderId")

    assert first_sender != account, (
        f"SenderId is the caller's ACCOUNT id ({account}); SQS documents it as the IAM user id or "
        f"IAM role id of the sender, which is a distinct value"
    )
    assert first_sender.strip(), f"SenderId came back blank: {first_sender!r}"

    assert first_sender == second_sender, (
        f"two sends by the SAME principal reported different SenderIds: {first_sender!r} then "
        f"{second_sender!r}. SenderId is a property of the caller, not of the message"
    )
    want_principal = user_id.split(":", 1)[0]
    got_principal = first_sender.split(":", 1)[0]
    assert got_principal == want_principal, (
        f"SenderId's principal-id component is {got_principal!r}, but this caller's "
        f"sts:GetCallerIdentity UserId is {user_id!r} (principal component {want_principal!r}). "
        f"SenderId must identify the principal that actually signed the SendMessage"
    )

    # Exact equality is asserted last: it is the leg most sensitive to the SenderId format.
    assert first_sender == user_id, (
        f"SenderId is {first_sender!r} but sts:GetCallerIdentity's UserId is {user_id!r}. The "
        f"ReceiveMessage reference documents SenderId as the IAM user id (for a user) or the IAM "
        f"role id in <role-id>:<session-name> form (for a role), which is the same value UserId "
        f"carries -- see this file's hypothesis 1 if real SQS disagrees"
    )

    first_sent_raw = _system_attribute(first, "SentTimestamp")
    assert first_sent_raw.isdigit(), (
        f"SentTimestamp must be a decimal epoch-milliseconds string, got {first_sent_raw!r}"
    )
    first_sent_ms = int(first_sent_raw)
    assert before_ms - _SKEW_MS <= first_sent_ms <= after_ms + _SKEW_MS, (
        f"SentTimestamp {first_sent_ms} is outside the window this run measured around its own "
        f"SendMessage call [{before_ms - _SKEW_MS}, {after_ms + _SKEW_MS}] (raw window "
        f"[{before_ms}, {after_ms}], skew allowance {_SKEW_MS}ms). A constant, a zero, or a value "
        f"replayed from a recording lands here"
    )

    # >= not >: two sends can share a millisecond.
    second_sent_ms = int(_system_attribute(second, "SentTimestamp"))
    assert second_sent_ms >= first_sent_ms, (
        f"the second send's SentTimestamp {second_sent_ms} precedes the first's {first_sent_ms}; "
        f"the stamped enqueue instant must not go backwards within one caller's program order"
    )

    sqs.delete_message(QueueUrl=url, ReceiptHandle=first["ReceiptHandle"])
    sqs.delete_message(QueueUrl=url, ReceiptHandle=second["ReceiptHandle"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
