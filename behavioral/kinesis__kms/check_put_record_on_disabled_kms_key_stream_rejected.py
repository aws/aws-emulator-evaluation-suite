"""put-record-on-disabled-kms-key-stream-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-on-disabled-kms-key-stream-rejected"
GROUP = "kinesis-sse-kms-permission-chain"
SERVICES = ["kinesis", "kms"]

_TAG = "sim2real-kinesis-kms-disabled"


# timing:real-time — ttl: 300 s https://aws.amazon.com/blogs/big-data/under-the-hood-of-server-side-encryption-for-amazon-kinesis-streams/
@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:data-plane", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Disabling the CMK an encrypted stream uses eventually refuses PutRecord with
    KMSDisabledException; re-enabling the same key restores writes, and the shard then holds
    exactly the records this check wrote, each decrypting to the plaintext it sent.

    Reference: https://docs.aws.amazon.com/kms/latest/APIReference/API_DisableKey.html
    """
    kinesis = ctx.client("kinesis")
    kms = ctx.client("kms")

    key_id, key_arn = _new_key(ctx, kms)
    stream = _new_stream(ctx, kinesis)
    shard_id = _only_shard_id(kinesis, stream)
    _start_encryption(kinesis, stream, key_arn)

    sent: dict[str, bytes] = {}
    control_seq = kinesis.put_record(StreamName=stream, Data=b"sim2real-enabled-payload",
                                      PartitionKey="pk-enabled")["SequenceNumber"]
    sent[control_seq] = b"sim2real-enabled-payload"
    before = len(_drain(kinesis, stream, shard_id))
    assert before == 1, f"after the control write the shard holds {before} record(s), expected 1"

    kms.disable_key(KeyId=key_id)
    # The KMS API is eventually consistent (AWS KMS DisableKey docs): PutRecord may keep
    # succeeding for a short window before the disabled state is enforced. Poll to that terminal
    # state rather than assuming the very next call already sees it, and keep every record a
    # still-converging call legitimately wrote.
    message = _poll_to_refusal(kinesis, stream, sent, partition_key="pk-disabling",
                                expected_code="KMSDisabledException")
    expected_message = f"{key_arn} is disabled."
    assert message == expected_message, f"unexpected refusal wording: {message!r}"

    kms.enable_key(KeyId=key_id)
    recovered = _poll(
        lambda: _outcome(lambda: kinesis.put_record(
            StreamName=stream, Data=b"sim2real-reenabled-payload", PartitionKey="pk-reenabled")),
        lambda o: o[0] == "OK", description="PutRecord after re-enabling the key")
    recovered_seq = recovered[1]["SequenceNumber"]
    sent[recovered_seq] = b"sim2real-reenabled-payload"

    # The independent read: an exact match against every write this check tracked is also the
    # absence proof for the disabled window, since any record the disabled key should have
    # blocked but did not would show up here as one neither sent captured nor matched by payload.
    records = _drain(kinesis, stream, shard_id)
    assert len(records) == len(sent), (
        f"the shard holds {len(records)} record(s) after recovery, expected the "
        f"{len(sent)} this check wrote")
    by_seq = {r["SequenceNumber"]: r["Data"] for r in records}
    for seq, payload in sent.items():
        assert by_seq.get(seq) == payload, (
            f"record {seq} decrypts to {by_seq.get(seq)!r}, expected the plaintext {payload!r} "
            f"this check sent")


def _new_key(ctx, kms) -> tuple[str, str]:
    key = kms.create_key(Description="sim2real kinesis SSE-KMS disabled-key rejection",
                          Tags=[{"TagKey": "sim2real", "TagValue": _TAG}])["KeyMetadata"]
    ctx.on_cleanup(lambda: _schedule_deletion(kms, key["KeyId"]))
    return key["KeyId"], key["Arn"]


def _schedule_deletion(kms, key_id: str) -> None:
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "KMSInvalidStateException":
            raise


def _new_stream(ctx, kinesis) -> str:
    name = ctx.unique_name("sim2real-kinesis-kms-disabled-")
    kinesis.create_stream(StreamName=name, ShardCount=1, Tags={"sim2real": _TAG})
    ctx.on_cleanup(_teardown(lambda: kinesis.delete_stream(StreamName=name),
                              "ResourceNotFoundException"))
    _poll(lambda: kinesis.describe_stream_summary(StreamName=name)
          ["StreamDescriptionSummary"]["StreamStatus"],
          lambda s: s == "ACTIVE", description=f"stream {name} reaching ACTIVE")
    return name


def _only_shard_id(kinesis, stream: str) -> str:
    """ListShards can still see CREATING for a moment after DescribeStreamSummary reports ACTIVE."""
    deadline = time.monotonic() + 30
    while True:
        try:
            shards = kinesis.list_shards(StreamName=stream)["Shards"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or (
                    time.monotonic() > deadline):
                raise
            time.sleep(2)
    assert len(shards) == 1, f"expected exactly one shard, found {len(shards)}: {shards!r}"
    return shards[0]["ShardId"]


def _start_encryption(kinesis, stream: str, key_arn: str) -> None:
    """A just-created CMK can read back as KMSNotFoundException for a few seconds; retry only that."""
    deadline = time.monotonic() + 60
    while True:
        try:
            kinesis.start_stream_encryption(StreamName=stream, EncryptionType="KMS", KeyId=key_arn)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "KMSNotFoundException" or (
                    time.monotonic() > deadline):
                raise
            time.sleep(3)
    _poll(lambda: kinesis.describe_stream_summary(StreamName=stream)
          ["StreamDescriptionSummary"]["StreamStatus"],
          lambda s: s == "ACTIVE", description=f"stream {stream} re-ACTIVE after StartStreamEncryption")


def _drain(kinesis, stream: str, shard_id: str, *, max_reads: int = 10) -> list[dict]:
    iterator = kinesis.get_shard_iterator(StreamName=stream, ShardId=shard_id,
                                           ShardIteratorType="TRIM_HORIZON")["ShardIterator"]
    records: list[dict] = []
    for _ in range(max_reads):
        resp = kinesis.get_records(ShardIterator=iterator, Limit=100)
        records.extend(resp["Records"])
        iterator = resp.get("NextShardIterator")
        if not iterator or (not resp["Records"] and resp.get("MillisBehindLatest", 0) == 0):
            break
        time.sleep(0.5)
    return records


def _outcome(fn):
    """("OK", value) on success, else (code, None). Only "OK" is compared for equality."""
    try:
        return "OK", fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], None


def _poll_to_refusal(kinesis, stream: str, sent: dict, *, partition_key: str, expected_code: str,
                      timeout_s: float = 420.0, interval_s: float = 3.0, confirm: int = 2) -> str:
    """Write distinctly-tagged records until ``expected_code`` is seen ``confirm`` times running.

    Kinesis caches the plaintext data key it derives from the CMK for up to 5 minutes (AWS's own
    account of SSE-KMS mechanics), so the first calls after disabling the key may still
    legitimately SUCCEED; every one that does is recorded in ``sent`` so the later independent
    read expects exactly what this check wrote, never a guessed "zero more" count. Returns the
    confirmed refusal's exact message.
    """
    deadline = time.monotonic() + timeout_s
    consecutive = 0
    message = None
    attempt = 0
    while True:
        attempt += 1
        try:
            seq = kinesis.put_record(StreamName=stream, Data=f"sim2real-transition-{attempt}".encode(),
                                      PartitionKey=f"{partition_key}-{attempt}")["SequenceNumber"]
            sent[seq] = f"sim2real-transition-{attempt}".encode()
            consecutive = 0
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != expected_code:
                raise AssertionError(f"expected {expected_code!r} once converged, got {code!r}")
            consecutive += 1
            message = exc.response["Error"].get("Message", "")
            if consecutive >= confirm:
                return message
        if time.monotonic() > deadline:
            raise AssertionError(
                f"PutRecord never settled into {confirm} consecutive {expected_code} refusals "
                f"within {timeout_s}s")
        time.sleep(interval_s)


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _poll(probe, predicate, *, timeout_s: float = 90.0, interval_s: float = 3.0,
          description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
