"""redrive-allow-policy-denyall-blocks-automatic-redrive-on-already-wired-source."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "redrive-allow-policy-denyall-blocks-automatic-redrive-on-already-wired-source"
GROUP = "dlq"
SERVICES = ["sqs"]

_TAGS = {"sim2real:managed": "true", "sim2real": "rap-denyall-blocks-auto-redrive"}
_OVER_RECEIVES = 4
_VISIBILITY_S = 1


def _await_attribute(sqs, url, name, expected, timeout_s=30.0):
    """Poll GetQueueAttributes until ``name`` reads back as the JSON document ``expected``."""
    deadline = time.monotonic() + timeout_s
    while True:
        raw = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=[name])["Attributes"].get(name)
        if raw is not None and json.loads(raw) == expected:
            return
        assert time.monotonic() < deadline, (
            f"{name} on {url!r} never read back as {expected!r} within {timeout_s}s; last {raw!r}"
        )
        time.sleep(1)


@tags(
    "axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:negative-classes",
    "dp:api", "plane:data",
)
def run(ctx) -> None:
    """RedriveAllowPolicy=denyAll on a DLQ stops the automatic maxReceiveCount redirect from an
    already-wired source: the message keeps being redelivered past the count and never lands in the
    DLQ; restoring allowAll lets one more over-count receive redirect it."""
    sqs = ctx.client("sqs")
    token = uuid.uuid4().hex[:8]

    dlq_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-dlq-"), tags=_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=dlq_url))
    dlq_arn = sqs.get_queue_attributes(QueueUrl=dlq_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    src_url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-src-"), tags=_TAGS)[
        "QueueUrl"
    ]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=src_url))
    src_arn = sqs.get_queue_attributes(QueueUrl=src_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    allow = {"redrivePermission": "byQueue", "sourceQueueArns": [src_arn]}
    sqs.set_queue_attributes(QueueUrl=dlq_url, Attributes={"RedriveAllowPolicy": json.dumps(allow)})
    redrive = {"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 1}
    sqs.set_queue_attributes(QueueUrl=src_url, Attributes={"RedrivePolicy": json.dumps(redrive)})
    _await_attribute(sqs, dlq_url, "RedriveAllowPolicy", allow)
    _await_attribute(sqs, src_url, "RedrivePolicy", redrive)

    # Revoke the allow policy BEFORE this message is ever received, so the whole lifecycle of
    # its over-count redelivery happens while denyAll is in effect.
    deny = {"redrivePermission": "denyAll"}
    sqs.set_queue_attributes(QueueUrl=dlq_url, Attributes={"RedriveAllowPolicy": json.dumps(deny)})
    _await_attribute(sqs, dlq_url, "RedriveAllowPolicy", deny)

    body = f"{token}-stuck"
    sqs.send_message(QueueUrl=src_url, MessageBody=body)

    # Each long poll outlasts the 1s visibility timeout, so it returns as soon as the message is
    # visible again rather than after a fixed sleep.
    for _ in range(_OVER_RECEIVES):
        r = sqs.receive_message(
            QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=_VISIBILITY_S + 4,
            VisibilityTimeout=_VISIBILITY_S,
        )
        msgs = r.get("Messages", [])
        assert len(msgs) == 1 and msgs[0]["Body"] == body, (
            f"expected {body!r} still delivered from the SOURCE (never redirected), got {msgs!r}"
        )

    dlq_peek = sqs.receive_message(QueueUrl=dlq_url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get(
        "Messages", []
    )
    assert dlq_peek == [], (
        f"RedriveAllowPolicy=denyAll must block the automatic redirect even {_OVER_RECEIVES}x "
        f"past maxReceiveCount=1, but a direct receive from the DLQ found {dlq_peek!r}"
    )

    # Positive control: restore the allow policy and force one more over-count receive -- the
    # identical message must now redirect, proving denyAll (not a dead RedrivePolicy) was why
    # it never did before.
    sqs.set_queue_attributes(QueueUrl=dlq_url, Attributes={"RedriveAllowPolicy": json.dumps(allow)})
    _await_attribute(sqs, dlq_url, "RedriveAllowPolicy", allow)

    moved = False
    for _ in range(8):
        r = sqs.receive_message(
            QueueUrl=src_url, MaxNumberOfMessages=1, WaitTimeSeconds=_VISIBILITY_S + 4,
            VisibilityTimeout=_VISIBILITY_S,
        )
        if not r.get("Messages"):
            moved = True
            break

    assert moved, f"after restoring the allow policy, {body!r} should have redirected to the DLQ"
    final_dlq = sqs.receive_message(QueueUrl=dlq_url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get(
        "Messages", []
    )
    assert len(final_dlq) == 1 and final_dlq[0]["Body"] == body, (
        f"positive control failed: expected {body!r} in the DLQ once the allow policy was "
        f"restored, got {final_dlq!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
