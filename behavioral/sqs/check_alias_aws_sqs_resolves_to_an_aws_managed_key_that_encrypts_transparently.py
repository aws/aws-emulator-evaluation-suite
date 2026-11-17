"""alias-aws-sqs-resolves-to-an-aws-managed-key-that-encrypts-transparently."""
from __future__ import annotations

import hashlib
import time

from behavioral_harness import tags

CHECK = "alias-aws-sqs-resolves-to-an-aws-managed-key-that-encrypts-transparently"
GROUP = "server-side"
SERVICES = ["sqs", "kms"]

_ALIAS = "alias/aws/sqs"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data",
      "plane:control")
def run(ctx) -> None:
    """alias/aws/sqs names a key KMS reports as AWS-managed, never created by the caller, and a
    queue configured with it encrypts messages that round-trip byte-exact in plaintext.
    """
    sqs = ctx.client("sqs")
    kms = ctx.client("kms")

    described = kms.describe_key(KeyId=_ALIAS)["KeyMetadata"]
    assert described["KeyManager"] == "AWS", (
        f"expected {_ALIAS!r} to be an AWS managed key, got KeyManager {described['KeyManager']!r}"
    )
    assert described["KeyState"] == "Enabled", (
        f"expected {_ALIAS!r} to be Enabled, got KeyState {described['KeyState']!r}"
    )
    assert described["Arn"] == f"arn:aws:kms:{ctx.region}:{ctx.account}:key/{described['KeyId']}", (
        f"unexpected key ARN {described['Arn']!r} for account {ctx.account!r}/region {ctx.region!r}"
    )

    found = None
    paginator = kms.get_paginator("list_aliases")
    for page in paginator.paginate():
        for alias in page["Aliases"]:
            if alias["AliasName"] == _ALIAS:
                found = alias
                break
        if found:
            break
    assert found is not None, f"{_ALIAS!r} is not present in this account's list_aliases"
    assert found["TargetKeyId"] == described["KeyId"], (
        f"list_aliases names target key {found['TargetKeyId']!r}, describe_key named "
        f"{described['KeyId']!r}"
    )

    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-behav-awsmanagedkey-"),
        Attributes={"KmsMasterKeyId": _ALIAS},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))

    configured = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["KmsMasterKeyId"])[
        "Attributes"
    ]["KmsMasterKeyId"]
    assert configured == _ALIAS, f"expected KmsMasterKeyId {_ALIAS!r}, got {configured!r}"

    body = "aws-managed-key-round-trip-🔑"
    want_md5 = hashlib.md5(body.encode("utf-8")).hexdigest()
    sent = sqs.send_message(QueueUrl=url, MessageBody=body)
    assert sent["MD5OfMessageBody"] == want_md5, (
        f"SendMessage's MD5OfMessageBody on an alias/aws/sqs queue must digest the PLAINTEXT body: "
        f"got {sent['MD5OfMessageBody']!r}, computed {want_md5!r}"
    )

    received = _poll_for_message(sqs, url)
    assert received["Body"] == body, f"received body {received['Body']!r}, expected {body!r}"
    assert received["MD5OfBody"] == want_md5, (
        f"ReceiveMessage's MD5OfBody must digest the PLAINTEXT body, not ciphertext: got "
        f"{received['MD5OfBody']!r}, computed {want_md5!r}"
    )
    sqs.delete_message(QueueUrl=url, ReceiptHandle=received["ReceiptHandle"])


def _poll_for_message(sqs, url, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        msgs = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=1, WaitTimeSeconds=5).get(
            "Messages", []
        )
        if msgs:
            return msgs[0]
    raise AssertionError("no message received within timeout")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
