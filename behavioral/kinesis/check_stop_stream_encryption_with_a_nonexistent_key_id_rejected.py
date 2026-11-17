"""stop-stream-encryption-with-a-nonexistent-key-id-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-stream-encryption-with-a-nonexistent-key-id-rejected"
GROUP = "encryption"
SERVICES = ["kinesis"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll(probe, pred, timeout_s=180.0, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")


def _absent_key_arn(stream_arn: str) -> str:
    """A syntactically valid KMS key ARN, in this account and region, that does not exist."""
    parts = stream_arn.split(":")
    partition, region, account = parts[1], parts[3], parts[4]
    return f"arn:{partition}:kms:{region}:{account}:key/00000000-0000-0000-0000-000000000000"


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """StopStreamEncryption rejects a nonexistent KeyId with InvalidArgumentException, even while
    the stream is actually encrypted under a different, real key, leaving the stream's own
    encryption state untouched; the matching KeyId then stops it.

    Reference: https://docs.aws.amazon.com/streams/latest/dev/getting-started-with-sse.html
    """
    kinesis = ctx.client("kinesis")

    name = ctx.unique_name("sim2real-behav-ssek-")
    kinesis.create_stream(
        StreamName=name, ShardCount=1, StreamModeDetails={"StreamMode": "PROVISIONED"}
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))

    def _summary():
        return kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]

    _poll(lambda: _summary()["StreamStatus"], lambda s: s == "ACTIVE", description="stream ACTIVE")
    stream_arn = _summary()["StreamARN"]

    kinesis.start_stream_encryption(StreamName=name, EncryptionType="KMS", KeyId="alias/aws/kinesis")
    encrypted = _poll(
        _summary, lambda s: s["StreamStatus"] == "ACTIVE" and s["EncryptionType"] == "KMS",
        description="stream ACTIVE with EncryptionType=KMS",
    )
    assert encrypted.get("KeyId") == "alias/aws/kinesis", (
        f"expected KeyId echoed back as 'alias/aws/kinesis', got {encrypted.get('KeyId')!r}"
    )

    bogus = _absent_key_arn(stream_arn)
    code, message = _error(
        lambda: kinesis.stop_stream_encryption(StreamName=name, EncryptionType="KMS", KeyId=bogus)
    )
    assert code == "InvalidArgumentException", (
        f"expected InvalidArgumentException stopping encryption with the nonexistent key "
        f"{bogus!r}, got {code}: {message!r}"
    )
    assert message == "Invalid keyId.", f"unexpected message {message!r}"

    unchanged = _summary()
    assert unchanged["StreamStatus"] == "ACTIVE", (
        f"the refused StopStreamEncryption left the stream as {unchanged['StreamStatus']!r}"
    )
    assert unchanged["EncryptionType"] == "KMS", (
        f"the refused StopStreamEncryption changed EncryptionType to "
        f"{unchanged['EncryptionType']!r}"
    )
    assert unchanged.get("KeyId") == "alias/aws/kinesis", (
        f"the refused StopStreamEncryption changed KeyId to {unchanged.get('KeyId')!r}"
    )

    # Positive control: the actual KeyId the stream is encrypted under does stop it.
    kinesis.stop_stream_encryption(StreamName=name, EncryptionType="KMS", KeyId="alias/aws/kinesis")
    disabled = _poll(
        _summary, lambda s: s["StreamStatus"] == "ACTIVE" and s["EncryptionType"] == "NONE",
        description="stream ACTIVE with EncryptionType=NONE",
    )
    assert disabled.get("KeyId") in (None, ""), (
        f"expected no KeyId once disabled, got {disabled.get('KeyId')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
