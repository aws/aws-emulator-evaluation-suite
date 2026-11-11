"""queue-policy-explicit-deny-blocks-send."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "queue-policy-explicit-deny-blocks-send"
GROUP = 'errors'
SERVICES = ['sqs']

# A resource-policy denial is HTTP 403 with Error.Code exactly "AccessDenied", not
# AccessDeniedException.
ERR_ACCESS_DENIED = "AccessDenied"


def _deny_message(caller_arn, queue_arn):
    """The exact denial message, which attributes the 403 to the resource policy, so an
    AccessDenied raised for an unrelated reason cannot satisfy the leg."""
    return (
        f"User: {caller_arn} is not authorized to perform: sqs:sendmessage on resource: "
        f"{queue_arn} with an explicit deny in a resource-based policy"
    )

# Adding a Deny to a queue that already has a policy can take ~120s to be enforced (removing it
# is near-instant), so a short window misreads propagation as "policies are not evaluated".
DENY_PROPAGATION_S = 300

_TAGS = {"sim2real:managed": "true", "sim2real": "queue-policy-explicit-deny-blocks-send"}


def _poll(fn, pred, *, timeout_s, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    val = fn()
    while not pred(val):
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)
        val = fn()
    return val


def _err(fn):
    """Return (Error.Code, Error.Message) for the ClientError fn raises; an unexpected success
    raises, so an accepted send is not reported as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be denied, but it SUCCEEDED and returned {result!r}")


def _until_sent(sqs, url, body, *, timeout_s, interval_s=1.0):
    """Send `body` until SendMessage accepts it; a refusal that outlasts the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sqs.send_message(QueueUrl=url, MessageBody=body)["MessageId"]
        except ClientError as exc:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"SendMessage was still refused after {timeout_s}s: {exc.response.get('Error')!r}"
                ) from exc
        time.sleep(interval_s)


def _drain(sqs, url, *, expect, timeout_s):
    seen = {}
    deadline = time.monotonic() + timeout_s
    while len(seen) < expect and time.monotonic() < deadline:
        for msg in sqs.receive_message(
            QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=1
        ).get("Messages", []):
            seen[msg["MessageId"]] = msg["Body"]
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return sorted(seen.values())


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An explicit Deny on sqs:SendMessage in the queue Policy blocks sends the identity allows, is
    scoped to that action, and removing it restores the send.

    Reference: https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html
    """
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-"), tags=_TAGS)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    parts = arn.split(":")
    assert len(parts) >= 6 and parts[4], f"cannot read the account id out of {arn!r}"
    account = parts[4]
    root = f"arn:aws:iam::{account}:root"
    # The denial message names the calling principal; read it rather than assume it.
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    allow_stmt = {
        "Sid": "AllowAccount",
        "Effect": "Allow",
        "Principal": {"AWS": root},
        "Action": "SQS:*",
        "Resource": arn,
    }
    # Never widen to sqs:* -- a Deny on everything also blocks the owner's DeleteQueue.
    deny_stmt = {
        "Sid": "DenySend",
        "Effect": "Deny",
        "Principal": {"AWS": root},
        "Action": "sqs:SendMessage",
        "Resource": arn,
    }

    def set_policy(statements):
        sqs.set_queue_attributes(
            QueueUrl=url,
            Attributes={
                "Policy": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Id": f"{arn}/sim2real-{uuid.uuid4().hex[:8]}",
                        "Statement": statements,
                    }
                )
            },
        )

    token = uuid.uuid4().hex[:8]

    # --- full valid setup: allow-only policy, and a send that works -------------------
    set_policy([allow_stmt])
    # The allow-only policy must not block SendMessage, or the deny leg below proves nothing.
    _until_sent(sqs, url, f"baseline-{token}", timeout_s=30)
    assert _drain(sqs, url, expect=1, timeout_s=20) == [
        f"baseline-{token}"
    ], "baseline message was not delivered"

    # --- break exactly one thing: add an explicit Deny on SendMessage -----------------
    set_policy([allow_stmt, deny_stmt])
    # Each probe send carries its OWN body, so the sends that land during the propagation window
    # can be accounted for exactly and drained; only the send made once the Deny is demonstrably
    # in effect is used for the effect-absent leg below.
    accepted: list[str] = []
    code = message = None
    deadline = time.monotonic() + DENY_PROPAGATION_S
    attempt = 0
    while True:
        attempt += 1
        probe = f"probe-{attempt}-{token}"
        try:
            sqs.send_message(QueueUrl=url, MessageBody=probe)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code, message = err.get("Code"), err.get("Message", "")
            break
        accepted.append(probe)
        if time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    assert code == ERR_ACCESS_DENIED, (
        f"an explicit Deny on sqs:SendMessage did not block the send within "
        f"{DENY_PROPAGATION_S}s and {attempt} attempts: got {code!r} "
        f"(None means the send succeeded)"
    )
    assert message == _deny_message(caller_arn, arn), (
        f"the 403 must be attributed to the resource policy, got {message!r}"
    )
    # Sends made before the Deny was enforced must have enqueued -- exactly them and nothing
    # else. This clears the queue so the denied send below has an empty queue to be absent from.
    if accepted:
        landed = _drain(
            sqs, url, expect=len(accepted), timeout_s=60
        )
        assert landed == sorted(accepted), (
            f"the {len(accepted)} send(s) accepted before the Deny took effect must all be "
            f"delivered and nothing else: {landed} != {sorted(accepted)}"
        )

    # --- effect absent: a send made with the Deny in force leaves nothing behind --------
    denied_code, denied_message = _err(
        lambda: sqs.send_message(QueueUrl=url, MessageBody=f"denied-{token}")
    )
    assert denied_code == ERR_ACCESS_DENIED, (
        f"the Deny stopped being enforced between two consecutive sends: {denied_code!r}"
    )
    assert denied_message == _deny_message(caller_arn, arn), f"got {denied_message!r}"
    # The counter needs a moment to reflect the drain above, so wait for it to settle on 0
    # rather than reading it immediately; the drain below is the stronger absence evidence.
    depth = _poll(
        lambda: sqs.get_queue_attributes(
            QueueUrl=url, AttributeNames=["ApproximateNumberOfMessages"]
        )["Attributes"].get("ApproximateNumberOfMessages", "?"),
        lambda v: v == "0",
        timeout_s=30,
    )
    assert depth == "0", f"denied send enqueued something: ApproximateNumberOfMessages={depth}"
    leaked = _drain(sqs, url, expect=1, timeout_s=10)
    assert leaked == [], f"denied send delivered {leaked}"

    # --- the Deny is action-scoped: other actions on the same queue still work --------
    recv = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=1)
    assert recv.get("Messages", []) == [], f"unexpected message present: {recv.get('Messages')}"
    attrs = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]
    assert attrs.get("QueueArn") == arn, (
        f"GetQueueAttributes was collaterally denied or changed: {attrs!r}"
    )

    # --- control: remove the Deny and the identical send succeeds again ---------------
    set_policy([allow_stmt])
    _until_sent(sqs, url, f"restored-{token}", timeout_s=DENY_PROPAGATION_S, interval_s=5.0)
    assert _drain(sqs, url, expect=1, timeout_s=20) == [
        f"restored-{token}"
    ], "control message was not delivered after the Deny was removed"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
