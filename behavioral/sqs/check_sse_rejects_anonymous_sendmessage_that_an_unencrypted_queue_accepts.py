"""sse-rejects-anonymous-sendmessage-that-an-unencrypted-queue-accepts."""
from __future__ import annotations

import json
import time

from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sse-rejects-anonymous-sendmessage-that-an-unencrypted-queue-accepts"
GROUP = "encryption"
SERVICES = ["sqs"]

_DENIED = (
    "AccessDenied",
    "Access to the resource The specified queue does not exist or you do not have access to "
    "it. is denied.",
)


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Principal * sqs:SendMessage grant, scoped to the caller's own IP, lets an UNSIGNED
    SendMessage land on an unencrypted queue; the identical call against an SSE-KMS queue
    carrying the same grant is refused and enqueues nothing."""
    sqs = ctx.client("sqs")
    cidrs = ctx.ingress_cidrs()

    plain_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-anon-plain-"),
        Attributes={"SqsManagedSseEnabled": "false"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=plain_url))
    plain_arn = sqs.get_queue_attributes(QueueUrl=plain_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]

    sse_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-anon-sse-"),
        Attributes={"KmsMasterKeyId": "alias/aws/sqs"},
        tags={"sim2real": CHECK},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=sse_url))
    sse_arn = sqs.get_queue_attributes(QueueUrl=sse_url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]

    _set_policy_and_wait(sqs, plain_url, _anon_send_policy(plain_arn, cidrs))
    _set_policy_and_wait(sqs, sse_url, _anon_send_policy(sse_arn, cidrs))

    unsigned_sqs = ctx.client("sqs", config=Config(signature_version=UNSIGNED))

    # positive control: the grant is IP-scoped and short-lived (removed with the queue in
    # cleanup); once it has propagated, the identical unsigned call succeeds on the
    # unencrypted queue.
    body = ctx.unique_name("unsigned-body-")
    sent = _until_allowed(lambda: unsigned_sqs.send_message(QueueUrl=plain_url, MessageBody=body))
    assert sent.get("MessageId"), f"the allowed unsigned SendMessage returned no MessageId: {sent!r}"

    # effect proven: the message really landed, with the body the unsigned caller sent.
    received = _receive_one(sqs, plain_url, timeout_s=30.0)
    assert received["Body"] == body, f"expected body {body!r} on the plain queue, got {received!r}"
    sqs.delete_message(QueueUrl=plain_url, ReceiptHandle=received["ReceiptHandle"])

    # negative: the identical unsigned call against the SSE-KMS queue, carrying the same
    # Principal * grant, is refused -- SSE blocks the caller the plain queue just admitted.
    err = _expect_denied(
        lambda: unsigned_sqs.send_message(QueueUrl=sse_url, MessageBody="unsigned-sse-body")
    )
    assert (err.get("Code"), err.get("Message")) == _DENIED, f"got {err!r}"

    # effect absent: nothing was enqueued on the SSE queue by the refused attempt.
    attrs = sqs.get_queue_attributes(
        QueueUrl=sse_url, AttributeNames=["ApproximateNumberOfMessages"]
    )["Attributes"]
    assert attrs["ApproximateNumberOfMessages"] == "0", (
        f"expected the refused SSE queue to hold no messages, got {attrs!r}"
    )


def _anon_send_policy(queue_arn, cidrs):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowScopedAnonymousSend",
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn,
                    "Condition": {"IpAddress": {"aws:SourceIp": cidrs}},
                }
            ],
        }
    )


def _canon(value):
    """A policy document with every scalar leaf wrapped as a one-element list -- AWS stores a
    single-element ``aws:SourceIp`` list back as a bare string, so the two forms must compare
    equal. A list of scalars sorts; a list of dicts (``Statement``) recurses and sorts by its
    own canonical form."""
    if isinstance(value, dict):
        return {k: _canon(v) for k, v in value.items()}
    if isinstance(value, list):
        if value and isinstance(value[0], dict):
            return sorted((_canon(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
        return sorted(value)
    return [value]


def _set_policy_and_wait(sqs, queue_url, policy_doc, *, timeout_s=60.0, interval_s=3.0):
    """SetQueueAttributes(Policy), then poll GetQueueAttributes until the control plane read
    confirms the same document -- a SetQueueAttributes 200 does not mean the read path agrees
    yet."""
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": policy_doc})
    wanted = _canon(json.loads(policy_doc))
    deadline = time.monotonic() + timeout_s
    while True:
        current = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["Policy"])[
            "Attributes"
        ].get("Policy")
        if current is not None and _canon(json.loads(current)) == wanted:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"queue policy on {queue_url} never read back as set")
        time.sleep(interval_s)


def _until_allowed(fn, *, timeout_s=90.0, interval_s=3.0):
    """Call ``fn`` until it stops raising the anonymous-denied error (policy propagation),
    bounded; any other failure raises immediately."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        try:
            return fn()
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if (error.get("Code"), error.get("Message")) != _DENIED:
                raise
            last = error
        if time.monotonic() > deadline:
            raise AssertionError(f"call never became allowed within {timeout_s}s (last={last!r})")
        time.sleep(interval_s)


def _expect_denied(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected this unsigned SendMessage to be denied, but it SUCCEEDED and returned {result!r}"
    )


def _receive_one(sqs, url, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=2).get(
            "Messages", []
        )
        if msgs:
            return msgs[0]
        time.sleep(interval_s)
    raise AssertionError(f"no message appeared on {url} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
