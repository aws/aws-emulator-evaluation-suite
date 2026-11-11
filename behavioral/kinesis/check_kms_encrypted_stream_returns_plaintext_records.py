"""kms-encrypted-stream-returns-plaintext-records."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


def _poll(probe, pred, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_stream_with_retry(c, name, **params):
    last_exc = None
    for attempt in range(12):
        try:
            c.create_stream(StreamName=name, **params)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "LimitExceededException":
                raise
            last_exc = exc
            time.sleep(min(5 + attempt * 2, 15))
    raise AssertionError(f"CreateStream kept hitting LimitExceededException for {name}: {last_exc}")


def _register_stream_teardown(ctx, c, name, timeout_s=300, interval_s=5):
    def _teardown():
        deadline = time.monotonic() + timeout_s
        last = None
        deleted = False
        while time.monotonic() < deadline:
            try:
                c.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
                deleted = True
                break
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code == "ResourceNotFoundException":
                    return
                if code not in ("ResourceInUseException", "LimitExceededException"):
                    raise
                last = code
                time.sleep(interval_s)
        if not deleted:
            raise AssertionError(
                f"stream {name} never reached a deletable state within {timeout_s}s "
                f"(last error {last}); it is still billing shard-hours"
            )
        while time.monotonic() < deadline:
            try:
                c.describe_stream_summary(StreamName=name)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                    return
                raise
            time.sleep(interval_s)
        raise AssertionError(
            f"stream {name} is still describable {timeout_s}s after DeleteStream returned; leak"
        )

    ctx.on_cleanup(_teardown)


def _summary(c, name):
    return c.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]


def _wait_stream_active(c, name, timeout_s=240, interval_s=2):
    _poll(
        lambda: _summary(c, name)["StreamStatus"],
        lambda status: status == "ACTIVE",
        timeout_s, interval_s, f"stream {name} ACTIVE",
    )


def _wait_stream_ready(c, name, timeout_s=240):
    _wait_stream_active(c, name, timeout_s=timeout_s)

    def _shards():
        try:
            return c.list_shards(StreamName=name)["Shards"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") in (
                "ResourceInUseException", "ResourceNotFoundException",
            ):
                return None
            raise

    _poll(_shards, lambda shards: bool(shards), 120, 2, f"stream {name} shards addressable")


def _provisioned_stream(ctx, c, shard_count=1):
    name = ctx.unique_name("sim2real-behav-kds-")
    _create_stream_with_retry(
        c, name, ShardCount=shard_count, StreamModeDetails={"StreamMode": "PROVISIONED"}
    )
    _register_stream_teardown(ctx, c, name)
    _wait_stream_ready(c, name)
    return name


def _shard_ids(c, name):
    return [s["ShardId"] for s in c.list_shards(StreamName=name)["Shards"]]


def _call_when_ready(fn, timeout_s=120, interval_s=2):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("ResourceNotFoundException", "ResourceInUseException") or (
                time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _put_until_encrypted(c, name, timeout_s=200, interval_s=5.0):
    """Retry PutRecord until the response reports EncryptionType=KMS; return every attempt.

    After StartStreamEncryption the stream is ACTIVE before per-shard encryption finishes
    propagating ("can take minutes"), so the next PutRecord may still report None.
    """
    deadline = time.monotonic() + timeout_s
    attempts = []
    attempt = 0
    while True:
        attempt += 1
        payload = f"plain-after-sse-{attempt}".encode()
        resp = c.put_record(StreamName=name, Data=payload, PartitionKey="k")
        attempts.append((payload, resp))
        if resp.get("EncryptionType") == "KMS":
            return attempts
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"PutRecord never reported EncryptionType=KMS across {attempt} attempts "
                f"over {timeout_s}s after StartStreamEncryption returned the stream to ACTIVE; "
                f"last response {resp!r}"
            )
        time.sleep(interval_s)


def _drain(c, iterator, want, timeout_s=180, interval_s=1.0, limit=1000):
    """Collect at least ``want`` records, chaining NextShardIterator across EMPTY pages."""
    collected = []
    pages = 0
    deadline = time.monotonic() + timeout_s
    while True:
        resp = c.get_records(ShardIterator=iterator, Limit=limit)
        pages += 1
        collected.extend(resp.get("Records", []))
        nxt = resp.get("NextShardIterator")
        if nxt is None:
            return collected, None, pages
        iterator = nxt
        if len(collected) >= want:
            return collected, iterator, pages
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"drained {pages} GetRecords pages over {timeout_s}s and saw "
                f"{len(collected)} of {want} expected records: "
                f"{[bytes(r['Data']) for r in collected]!r}"
            )
        time.sleep(interval_s)


def _absent_key_arn(stream_arn):
    """A syntactically valid KMS key ARN, in this account and region, that does not exist.

    Built from the stream's ARN so it is refused for key resolution, not access or syntax.
    """
    parts = stream_arn.split(":")
    partition, region, account = parts[1], parts[3], parts[4]
    return f"arn:{partition}:kms:{region}:{account}:key/00000000-0000-0000-0000-000000000000"


CHECK = "kms-encrypted-stream-returns-plaintext-records"
GROUP = 'encryption'
SERVICES = ['kinesis']


def _start_encryption_with_new_key(ctx, client, stream_name, key_id):
    """StartStreamEncryption with a key created moments before; Kinesis may not resolve a new
    key for a few seconds, so KMSNotFoundException is retried for up to 60 s, within the budget."""
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else max(0.0, min(60.0, left - 10.0)))
    while True:
        try:
            return client.start_stream_encryption(
                StreamName=stream_name, EncryptionType="KMS", KeyId=key_id
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KMSNotFoundException":
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(3)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartStreamEncryption with a nonexistent key ARN is refused with KMSNotFoundException and
    leaves the stream unencrypted; with a customer managed key, GetRecords returns every record put
    before and after as the exact plaintext bytes, the last labelled EncryptionType=KMS.
    """
    c = ctx.client("kinesis")
    name = _provisioned_stream(ctx, c, shard_count=1)
    shard_id = _shard_ids(c, name)[0]
    stream_arn = _summary(c, name)["StreamARN"]

    before = _summary(c, name)
    assert before["EncryptionType"] == "NONE", (
        f"a freshly created stream must start unencrypted, got "
        f"EncryptionType={before['EncryptionType']}"
    )
    put_before = _call_when_ready(
        lambda: c.put_record(StreamName=name, Data=b"plain-before-sse", PartitionKey="k")
    )

    bogus = _absent_key_arn(stream_arn)
    try:
        c.start_stream_encryption(
            StreamName=name, EncryptionType="KMS", KeyId=bogus
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        assert code == "KMSNotFoundException", (
            f"StartStreamEncryption with the nonexistent key {bogus} failed with {code}; "
            f"expected KMSNotFoundException (alternative under confirmation: "
            f"InvalidArgumentException)"
        )
        message = exc.response.get("Error", {}).get("Message")
        expected_message = f"Key '{bogus}' does not exist"
        assert message == expected_message, (
            f"expected message {expected_message!r}, got {message!r}"
        )
    else:
        raise AssertionError(
            f"StartStreamEncryption ACCEPTED the nonexistent key {bogus}; real AWS resolves "
            f"the KeyId against KMS and refuses. Accepting it yields a stream that reports "
            f"itself encrypted with a key nobody can use"
        )

    after_refusal = _summary(c, name)
    assert after_refusal["EncryptionType"] == "NONE", (
        f"the refused StartStreamEncryption still changed EncryptionType to "
        f"{after_refusal['EncryptionType']}"
    )
    assert "KeyId" not in after_refusal, (
        f"the refused StartStreamEncryption recorded KeyId={after_refusal.get('KeyId')} on "
        f"an unencrypted stream"
    )
    assert after_refusal["StreamStatus"] == "ACTIVE", (
        f"the refused StartStreamEncryption moved the stream to "
        f"{after_refusal['StreamStatus']}; a rejected request must not start an update"
    )

    kms = ctx.client("kms")
    key_id = kms.create_key(Description=name)["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    # The check's own alias: Kinesis echoes the KeyId it was given verbatim, alias name included.
    alias = f"alias/{ctx.unique_name('sim2real-kinesis-')}"
    kms.create_alias(AliasName=alias, TargetKeyId=key_id)
    ctx.on_cleanup(lambda: kms.delete_alias(AliasName=alias))
    _start_encryption_with_new_key(ctx, c, name, alias)
    _wait_stream_active(c, name)
    encrypted = _summary(c, name)
    assert encrypted["EncryptionType"] == "KMS", (
        f"after a successful StartStreamEncryption the summary reports "
        f"EncryptionType={encrypted['EncryptionType']}, expected KMS"
    )
    assert encrypted.get("KeyId") == alias, (
        f"the summary reports KeyId={encrypted.get('KeyId')!r}, expected the requested "
        f"{alias!r} echoed back verbatim"
    )

    put_attempts = _put_until_encrypted(c, name)
    put_after_payload, put_after = put_attempts[-1]
    assert int(put_after["SequenceNumber"]) > int(put_before["SequenceNumber"]), (
        f"the post-encryption record's sequence number {put_after['SequenceNumber']} does not "
        f"advance past the pre-encryption one {put_before['SequenceNumber']}; enabling SSE "
        f"must not restart the shard's sequence"
    )

    iterator = c.get_shard_iterator(
        StreamName=name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    want = 1 + len(put_attempts)
    recs, _it, pages = _drain(c, iterator, want=want)
    got = [bytes(r["Data"]) for r in recs]
    expected = [b"plain-before-sse"] + [payload for payload, _resp in put_attempts]
    assert got == expected, (
        f"GetRecords on the encrypted stream returned {got!r} over {pages} pages; SSE-KMS is "
        f"transparent, so every payload put — pre- and post-encryption, including any retry "
        f"while the per-shard encryption path was still propagating — must come back as the "
        f"exact plaintext bytes that were put, in order; expected {expected!r}"
    )
    assert recs[-1].get("EncryptionType") == "KMS", (
        f"the record whose PutRecord response first confirmed EncryptionType=KMS "
        f"({put_after_payload!r}) reports EncryptionType={recs[-1].get('EncryptionType')!r} on "
        f"read, expected KMS"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
