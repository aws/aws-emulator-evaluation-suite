"""kms-key-permission-gates-send-message."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kms-key-permission-gates-send-message"
GROUP = "overly-permissive"
SERVICES = ["sqs"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendMessage on an SSE-KMS queue whose key policy denies GenerateDataKey fails with
    KMS.AccessDeniedException; an SQS-managed SSE queue still delivers, and removing the Deny from
    the same key restores delivery on the same queue."""
    sqs = ctx.client("sqs")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    caller = sts.get_caller_identity()
    account_id = caller["Account"]

    key_tag = ctx.unique_name("sim2real-behav-key-")
    root_statement = {
        "Sid": "EnableRootPermissions",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
        "Action": "kms:*",
        "Resource": "*",
    }
    deny_statement = {
        "Sid": "DenyDataKeyUsage",
        "Effect": "Deny",
        "Principal": "*",
        "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
        "Resource": "*",
    }
    key = kms.create_key(
        Policy=json.dumps({"Version": "2012-10-17", "Statement": [root_statement, deny_statement]}),
        Description=key_tag,
        Tags=[{"TagKey": "sim2real", "TagValue": key_tag}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    denied_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-denied-"), Attributes={"KmsMasterKeyId": key_id}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=denied_url))
    sqs.tag_queue(QueueUrl=denied_url, Tags={"sim2real": key_tag})

    def _attempt():
        try:
            sqs.send_message(QueueUrl=denied_url, MessageBody="should-be-blocked-by-kms")
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        return None

    # New KMS key policies can take a short time to take effect; poll for the failure.
    code, message = _poll_until(_attempt, lambda c: c is not None, timeout_s=60.0, interval_s=3.0)
    assert code == "KMS.AccessDeniedException", f"expected KMS.AccessDeniedException, got {code!r}"
    # The relayed KMS refusal carries KMS's own request id, which differs per call.
    denied_prefix = (
        f"User: {caller['Arn']} is not authorized to perform: kms:GenerateDataKey on resource: "
        f"{key['KeyMetadata']['Arn']} with an explicit deny in a resource-based policy (Service: "
        "AWSKMS; Status Code: 400; Error Code: AccessDeniedException; Request ID: "
    )
    request_id = (message or "")[len(denied_prefix):-len("; Proxy: null)")]
    assert re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", request_id), (
        f"expected the KMS request id after {denied_prefix!r}, got {message!r}"
    )
    assert message == f"{denied_prefix}{request_id}; Proxy: null)", (
        f"expected the KMS refusal message for key {key_id}, got {message!r}"
    )

    # Effect absent: nothing landed on the KMS-blocked queue.
    leftover = sqs.receive_message(QueueUrl=denied_url, MaxNumberOfMessages=10, WaitTimeSeconds=2).get(
        "Messages", []
    )
    assert leftover == [], f"expected no messages on the KMS-blocked queue, got {leftover!r}"

    # Positive control: a queue using the AWS-managed SQS SSE key sends/receives normally,
    # proving the account and SQS wiring are otherwise healthy (this is not "every send fails").
    open_url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-open-"), Attributes={"SqsManagedSseEnabled": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=open_url))
    sqs.tag_queue(QueueUrl=open_url, Tags={"sim2real": key_tag})
    sqs.send_message(QueueUrl=open_url, MessageBody="should-land-fine")
    landed = _poll_until(
        lambda: sqs.receive_message(QueueUrl=open_url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get(
            "Messages", []
        ),
        lambda msgs: len(msgs) == 1,
        timeout_s=20.0,
    )
    assert landed[0]["Body"] == "should-land-fine", f"expected 'should-land-fine', got {landed[0]!r}"
    sqs.delete_message(QueueUrl=open_url, ReceiptHandle=landed[0]["ReceiptHandle"])

    # Restore: remove the Deny statement from the SAME key. The identical call against the SAME
    # queue that failed above must now succeed, and the message must actually land.
    kms.put_key_policy(
        KeyId=key_id,
        PolicyName="default",
        Policy=json.dumps({"Version": "2012-10-17", "Statement": [root_statement]}),
    )
    restored = _poll_until(_attempt, lambda c: c is None, timeout_s=60.0, interval_s=3.0)
    assert restored is None, f"expected SendMessage to succeed once the Deny was removed, got {restored!r}"
    delivered = _poll_until(
        lambda: sqs.receive_message(QueueUrl=denied_url, MaxNumberOfMessages=10, WaitTimeSeconds=5).get(
            "Messages", []
        ),
        lambda msgs: len(msgs) >= 1,
        timeout_s=30.0,
    )
    bodies = {m["Body"] for m in delivered}
    assert "should-be-blocked-by-kms" in bodies, f"expected the restored send to land, got {bodies!r}"
    for m in delivered:
        sqs.delete_message(QueueUrl=denied_url, ReceiptHandle=m["ReceiptHandle"])


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
