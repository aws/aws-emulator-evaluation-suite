"""managed-key-alias-aws-kinesis-backs-encryption-without-a-caller-create."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "managed-key-alias-aws-kinesis-backs-encryption-without-a-caller-create"
GROUP = "encryption"
SERVICES = ["kinesis", "kms", "sts"]


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


def _list_shards(kinesis, name, timeout_s=60.0, interval_s=2.0):
    """ListShards, retrying the transient ResourceInUseException a just-ACTIVE stream can still
    raise while its shard-map view catches up with its status view."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return kinesis.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            err = exc.response["Error"]
            transient = err["Code"] == "ResourceInUseException" and (
                "CREATING" in err.get("Message", "") or "UPDATING" in err.get("Message", "")
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _drain(kinesis, iterator, want, timeout_s=120.0, interval_s=1.0):
    """Every record collected from ``iterator`` on, chaining NextShardIterator across EMPTY pages."""
    collected = []
    deadline = time.monotonic() + timeout_s
    while True:
        resp = kinesis.get_records(ShardIterator=iterator, Limit=1000)
        collected.extend(resp["Records"])
        nxt = resp.get("NextShardIterator")
        if len(collected) >= want or nxt is None:
            return collected
        iterator = nxt
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"drained {len(collected)} of {want} expected record(s) within {timeout_s}s"
            )
        time.sleep(interval_s)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """StartStreamEncryption against KeyId "alias/aws/kinesis" needs no key the caller created:
    AWS resolves it to an AWS-managed key whose resource policy denies DisableKey to the caller,
    where a customer-managed key accepts the identical call.

    Reference: https://docs.aws.amazon.com/streams/latest/dev/getting-started-with-sse.html
    Reference: https://docs.aws.amazon.com/kms/latest/developerguide/enabling-keys.html
    """
    kinesis = ctx.client("kinesis")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    caller_arn = sts.get_caller_identity()["Arn"]

    # Legal-neighbour control: a key the caller *did* create can be disabled and re-enabled.
    customer_key_id = kms.create_key(Description=ctx.unique_name("sim2real-behav-kmgd-cmk-"))[
        "KeyMetadata"
    ]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=customer_key_id, PendingWindowInDays=7))
    kms.disable_key(KeyId=customer_key_id)
    disabled_state = kms.describe_key(KeyId=customer_key_id)["KeyMetadata"]["KeyState"]
    assert disabled_state == "Disabled", (
        f"expected the customer-managed key to report KeyState=Disabled after DisableKey, "
        f"got {disabled_state!r}"
    )
    kms.enable_key(KeyId=customer_key_id)

    name = ctx.unique_name("sim2real-behav-kmgd-")
    kinesis.create_stream(
        StreamName=name, ShardCount=1, StreamModeDetails={"StreamMode": "PROVISIONED"}
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))

    def _summary():
        return kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]

    _poll(lambda: _summary()["StreamStatus"], lambda s: s == "ACTIVE", description="stream ACTIVE")
    shard_id = _list_shards(kinesis, name)[0]["ShardId"]

    before = kinesis.put_record(StreamName=name, Data=b"plain-before-managed-sse", PartitionKey="k")
    assert before.get("EncryptionType") in (None, "NONE"), (
        f"expected no encryption before StartStreamEncryption, got "
        f"{before.get('EncryptionType')!r}"
    )

    # Starting encryption with the Kinesis-owned alias is the only "create": the caller never
    # calls kms.create_key for this key.
    kinesis.start_stream_encryption(StreamName=name, EncryptionType="KMS", KeyId="alias/aws/kinesis")
    encrypted = _poll(
        _summary, lambda s: s["StreamStatus"] == "ACTIVE",
        description="stream ACTIVE after StartStreamEncryption",
    )
    assert encrypted["EncryptionType"] == "KMS", (
        f"expected EncryptionType=KMS after StartStreamEncryption, got "
        f"{encrypted['EncryptionType']!r}"
    )
    assert encrypted.get("KeyId") == "alias/aws/kinesis", (
        f"expected KeyId echoed back as 'alias/aws/kinesis', got {encrypted.get('KeyId')!r}"
    )

    # The only way to learn anything about the key behind that alias: DescribeKey. The caller
    # never created it, so whatever this reports is AWS's own doing, not ours.
    managed_key = kms.describe_key(KeyId="alias/aws/kinesis")["KeyMetadata"]
    assert managed_key["KeyManager"] == "AWS", (
        f"expected the key behind alias/aws/kinesis to be AWS-managed, got KeyManager="
        f"{managed_key['KeyManager']!r}"
    )
    assert managed_key["AWSAccountId"] == ctx.account, (
        f"expected the managed key to belong to this account ({ctx.account!r}), got "
        f"AWSAccountId={managed_key['AWSAccountId']!r}"
    )
    assert managed_key["KeyState"] == "Enabled", (
        f"expected the managed key to be enabled, got KeyState={managed_key['KeyState']!r}"
    )

    # The refusal under test: unlike the customer-managed key above, this one cannot be disabled.
    # DisableKey takes a key id/ARN, not an alias, so resolve the alias the same DescribeKey
    # response already gave us.
    managed_key_id = managed_key["KeyId"]
    managed_key_arn = managed_key["Arn"]
    code, message = _error(lambda: kms.disable_key(KeyId=managed_key_id))
    assert code == "AccessDeniedException", (
        f"expected AccessDeniedException disabling the AWS-managed key, got {code}: {message!r}"
    )
    expected_message = (
        f"User: {caller_arn} is not authorized to perform: kms:DisableKey on resource: "
        f"{managed_key_arn} because no resource-based policy allows the kms:DisableKey action"
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # The refused call changed nothing: the managed key is still enabled and the stream's data
    # plane is still transparently encrypting with it.
    still_enabled = kms.describe_key(KeyId="alias/aws/kinesis")["KeyMetadata"]["KeyState"]
    assert still_enabled == "Enabled", (
        f"the refused DisableKey left the managed key as KeyState={still_enabled!r}"
    )

    # Each retry attempt is its own record with its own payload: per-shard encryption can still be
    # propagating when PutRecord returns, so a retry must not resend the same payload twice.
    after_payloads = []
    deadline = time.monotonic() + 180.0
    attempt = 0
    while True:
        attempt += 1
        payload = f"plain-after-managed-sse-{attempt}".encode()
        put_after = kinesis.put_record(StreamName=name, Data=payload, PartitionKey="k")
        after_payloads.append(payload)
        if put_after.get("EncryptionType") == "KMS":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"PutRecord never reported EncryptionType=KMS within 180s across "
                f"{attempt} attempt(s); last {put_after!r}"
            )
        time.sleep(3)

    iterator = kinesis.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    records = _drain(kinesis, iterator, want=1 + len(after_payloads))
    got = [bytes(r["Data"]) for r in records]
    expected = [b"plain-before-managed-sse"] + after_payloads
    assert got == expected, (
        f"expected every record back as exact plaintext in put order, got {got!r}, "
        f"expected {expected!r}"
    )
    assert records[-1].get("EncryptionType") == "KMS", (
        f"expected the last record to report EncryptionType=KMS on read, got "
        f"{records[-1].get('EncryptionType')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
