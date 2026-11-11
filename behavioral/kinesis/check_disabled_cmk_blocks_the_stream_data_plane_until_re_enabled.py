"""disabled-cmk-blocks-the-stream-data-plane-until-re-enabled."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "disabled-cmk-blocks-the-stream-data-plane-until-re-enabled"
GROUP = "encryption"
SERVICES = ["kinesis"]

# AWS behavior this check pins:
#   1. WALL CLOCK. Kinesis rotates data keys on its own ~5-minute cadence (per credential), not
#      synchronized to the moment this check disables the CMK, so the refusal window is 900 s
#      (3x the documented cadence). Teardown is two DeleteStream calls and one ScheduleKeyDeletion;
#      the KMS key lingers as PendingDeletion for the 7-day minimum window KMS allows.
#   2. A DISABLED customer-managed CMK makes PutRecord and GetRecords refuse with
#      KMSDisabledException, not KMSInvalidStateException.
#   3. StartStreamEncryption against the same disabled CMK does not report the data plane's
#      KMSDisabledException. It validates key state synchronously at call time and rejects with
#      InvalidArgumentException ("Key is not enabled."), because that validation never attempts the
#      GenerateDataKey/Decrypt call the wrapped KMS exception comes from. Both codes are modelled as
#      siblings on StartStreamEncryption (com.amazonaws.kinesis, 2013-12-02).
#   4. PutRecord and GetRecords refuse with the identical code; the check does not order them.
#   5. A CMK created with the DEFAULT key policy (account root) is usable by this check's principal
#      for Kinesis SSE: StartStreamEncryption succeeds with no KMSAccessDenied.
#   6. The shard's terminal contents are exactly the pre-disable record, every probe record
#      accepted during the window, then the post-restore record, in that order, all readable as
#      plaintext whether written under EncryptionType NONE or KMS.

_PRE = b"kms-pre-disable"
_POST = b"kms-post-restore"
_PARTITION_KEY = "kms-pk"
#: How long Kinesis's cached data key may keep the disabled CMK invisible (item 1 above). AWS's
#: docs say Kinesis calls KMS to rotate the data key "approximately every five minutes" per
#: credential, on its own clock since encryption was enabled and not synchronized to the moment
#: this check disables the CMK, so the worst case can be up to one full cycle after an unlucky
#: offset. The window is 3x the documented cycle.
_KMS_PROPAGATION_S = 900.0
_READ_REFUSAL_S = 90.0


# timing:real-time — ttl: 300 s https://docs.aws.amazon.com/streams/latest/dev/what-is-sse.html
@tags(
    "axis:rejection",
    "cap:c1",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:control",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """Disabling the customer-managed CMK behind a Kinesis stream's SSE makes the stream's data
    plane refuse with a specific KMS error on both write and read, and re-enabling the key restores
    the identical calls — the stored KeyId is not just a label."""
    kinesis = ctx.client("kinesis")
    kms = ctx.client("kms")
    key = _create_cmk(ctx)
    subject = _create_active_stream(ctx)
    bystander = _create_active_stream(ctx)
    shard_id = _single_shard_id(ctx, subject["name"])

    kinesis.start_stream_encryption(
        StreamName=subject["name"], EncryptionType="KMS", KeyId=key["arn"]
    )
    summary = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=subject["name"])[
            "StreamDescriptionSummary"
        ],
        lambda s: s["StreamStatus"] == "ACTIVE" and s.get("EncryptionType") == "KMS",
        timeout_s=300.0,
        interval_s=5.0,
        description=f"stream {subject['name']} to report EncryptionType=KMS while ACTIVE",
    )
    assert summary.get("KeyId") == key["arn"], (
        f"DescribeStreamSummary reports KeyId {summary.get('KeyId')!r}; expected the CMK ARN "
        f"{key['arn']!r}"
    )

    # ---- Positive control: the whole data plane works with the CMK ENABLED ----
    # DescribeStreamSummary reporting ACTIVE+KMS does not guarantee the very next record is
    # already encrypted: a record written right after that confirmation can read back with NO
    # EncryptionType tag at all (plaintext), and re-reading that SAME record does not change it
    # — so the race is in the WRITE settling, not in a read-side tag lag.
    # This retries the write instead: every record it puts genuinely lands in the shard whether or
    # not it came back encrypted, so all of them are folded into the terminal exact-contents
    # assertion below rather than discarded.
    pre_records: list[bytes] = []

    def _probe_pre() -> dict | None:
        payload = _PRE if not pre_records else f"kms-pre-settle-{len(pre_records)}".encode()
        kinesis.put_record(StreamName=subject["name"], Data=payload, PartitionKey=_PARTITION_KEY)
        pre_records.append(payload)
        rec = _read_records(ctx, subject["name"], shard_id, expect=len(pre_records))[-1]
        return rec if rec.get("EncryptionType") == "KMS" else None

    control = _poll_until(
        _probe_pre,
        lambda rec: rec is not None,
        timeout_s=60.0,
        interval_s=3.0,
        description=(
            f"a record on {subject['name']} to read back tagged EncryptionType=KMS — ACTIVE+KMS "
            "on DescribeStreamSummary does not guarantee the very next write already is"
        ),
    )
    pre_seq = control["SequenceNumber"]
    assert control["Data"] == pre_records[-1], (
        f"positive control: the confirmed-encrypted record reads back {control['Data']!r}; "
        f"expected {pre_records[-1]!r}"
    )
    assert control["EncryptionType"] == "KMS", (
        f"positive control: the record reports EncryptionType {control.get('EncryptionType')!r}; "
        "expected 'KMS'"
    )

    # ---- Break exactly one thing: disable the CMK. Nothing about the stream changes ----
    kms.disable_key(KeyId=key["id"])
    _poll_until(
        lambda: kms.describe_key(KeyId=key["id"])["KeyMetadata"]["KeyState"],
        lambda state: state == "Disabled",
        timeout_s=60.0,
        interval_s=2.0,
        description=f"CMK {key['id']} to report KeyState=Disabled",
    )

    accepted_probes: list[bytes] = []
    write_refusal: dict = {}
    disable_started = time.monotonic()

    def _put_refused() -> bool:
        """Try a real PutRecord; True once it is refused, with the error kept in write_refusal.

        A still-accepted put means Kinesis is serving from its cached data key; the payload is
        recorded so the terminal assertion can account for it exactly.
        """
        payload = f"kms-probe-{len(accepted_probes)}".encode()
        try:
            kinesis.put_record(
                StreamName=subject["name"], Data=payload, PartitionKey=_PARTITION_KEY
            )
        except ClientError as exc:
            write_refusal.update(exc.response.get("Error", {}))
            return True
        accepted_probes.append(payload)
        return False

    _poll_until(
        _put_refused,
        bool,
        timeout_s=_KMS_PROPAGATION_S,
        interval_s=15.0,
        description=(
            f"PutRecord on {subject['name']} to start refusing now that its CMK is DISABLED "
            "(Kinesis caches the data key, so this is not instant)"
        ),
    )
    disable_latency_s = time.monotonic() - disable_started
    write_code = write_refusal.get("Code")
    assert write_code == "KMSDisabledException", (
        f"PutRecord against a stream whose CMK is disabled failed with {write_code!r}; expected "
        f"KMSDisabledException (the alternative under confirmation is KMSInvalidStateException — "
        "see hypothesis 2)"
    )
    expected_disabled_message = f"{key['arn']} is disabled."
    assert write_refusal.get("Message") == expected_disabled_message, (
        f"PutRecord refusal message was {write_refusal.get('Message')!r}; expected "
        f"{expected_disabled_message!r}"
    )

    # ---- Second independent observable: the READ path is refused too ----
    read_refusal: dict = {}
    _poll_until(
        lambda: _read_refused(ctx, subject["name"], shard_id, read_refusal),
        bool,
        timeout_s=_READ_REFUSAL_S,
        interval_s=5.0,
        description=(
            f"GetRecords on {subject['name']} to start refusing with the CMK disabled — the "
            "already-written records cannot be decrypted"
        ),
    )
    read_code = read_refusal.get("Code")
    assert read_code == write_code, (
        f"GetRecords was refused with {read_code!r} while PutRecord was refused with "
        f"{write_code!r}; both paths depend on the same disabled CMK and must report the same code"
    )
    assert read_refusal.get("Message") == expected_disabled_message, (
        f"GetRecords refusal message was {read_refusal.get('Message')!r}; expected "
        f"{expected_disabled_message!r}"
    )

    # ---- Fast control-plane leg: a disabled key cannot be attached at all ----
    # Not the same code as the data plane: StartStreamEncryption validates the key's
    # state synchronously against KMS at call time and rejects with InvalidArgumentException,
    # "Key is not enabled." — it never reaches the wrapped KMSDisabledException the data plane
    # reports, because that code is reserved for a failed GenerateDataKey/Decrypt call, and the
    # control plane refuses before ever attempting one. Both are modelled on this operation
    # (com.amazonaws.kinesis, 2013-12-02 lists InvalidArgumentException and KMSDisabledException as
    # sibling errors on StartStreamEncryption); AWS picked the generic one here.
    err = _client_error(
        lambda: kinesis.start_stream_encryption(
            StreamName=bystander["name"], EncryptionType="KMS", KeyId=key["arn"]
        )
    )
    assert err.get("Code") == "InvalidArgumentException", (
        f"StartStreamEncryption with a DISABLED CMK failed with {err.get('Code')!r}; expected "
        f"'InvalidArgumentException' (the control plane validates key state synchronously and "
        f"never reaches the data plane's {write_code!r}): {err.get('Message')!r}"
    )
    assert err.get("Message") == "Key is not enabled.", (
        f"StartStreamEncryption's InvalidArgumentException message was {err.get('Message')!r}; "
        "expected 'Key is not enabled.'"
    )
    bystander_summary = kinesis.describe_stream_summary(StreamName=bystander["name"])[
        "StreamDescriptionSummary"
    ]
    assert bystander_summary.get("EncryptionType") == "NONE", (
        f"after the refused StartStreamEncryption, {bystander['name']} reports EncryptionType "
        f"{bystander_summary.get('EncryptionType')!r}; expected 'NONE' — a refused call must not "
        "half-apply"
    )
    assert "KeyId" not in bystander_summary, (
        f"after the refused StartStreamEncryption, {bystander['name']} reports KeyId "
        f"{bystander_summary.get('KeyId')!r}; expected no KeyId at all"
    )

    # ---- Restore exactly the broken thing, and demand the identical calls succeed ----
    kms.enable_key(KeyId=key["id"])
    _poll_until(
        lambda: kms.describe_key(KeyId=key["id"])["KeyMetadata"]["KeyState"],
        lambda state: state == "Enabled",
        timeout_s=60.0,
        interval_s=2.0,
        description=f"CMK {key['id']} to report KeyState=Enabled again",
    )
    restore_deadline = max(3.0 * disable_latency_s, 120.0)
    post_seq = _poll_until(
        lambda: _put_or_none(kinesis, subject["name"], _POST),
        lambda seq: seq is not None,
        timeout_s=restore_deadline,
        interval_s=15.0,
        description=(
            f"PutRecord on {subject['name']} to succeed again within {restore_deadline:.0f}s "
            f"(3x the {disable_latency_s:.0f}s the refusal itself took to appear)"
        ),
    )
    assert int(post_seq) > int(pre_seq), (
        f"the post-restore record's sequence number {post_seq} is not greater than the "
        f"pre-disable record's {pre_seq}"
    )

    # ---- Terminal independent read: exactly what was accepted, in order, as plaintext ----
    expected = [*pre_records, *accepted_probes, _POST]
    records = _read_records(ctx, subject["name"], shard_id, expect=len(expected))
    payloads = [r["Data"] for r in records]
    assert payloads == expected, (
        f"the shard's final contents are {payloads!r}; expected {expected!r} — every pre-disable "
        f"settling attempt ({len(pre_records)}), the {len(accepted_probes)} probe puts this run "
        "OBSERVED being accepted, and the post-restore record, in write order, with every refused "
        "put absent"
    )
    # The settling attempts before the confirmed one are expected to still be plaintext — that is
    # exactly the race the retry above exists to tolerate, not paper over.
    unsettled, settled = records[: len(pre_records) - 1], records[len(pre_records) - 1 :]
    assert all(r.get("EncryptionType") != "KMS" for r in unsettled), (
        "a pre-disable settling record reports EncryptionType=='KMS' unexpectedly — it should "
        f"have been one of the still-plaintext attempts made while encryption settled: "
        f"{[r.get('EncryptionType') for r in unsettled]!r}"
    )
    assert all(r["EncryptionType"] == "KMS" for r in settled), (
        "at least one record from the confirmed-encrypted point onward reports EncryptionType != "
        f"'KMS': {[r.get('EncryptionType') for r in settled]!r}"
    )


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    """Bounded retry that RAISES on timeout — never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}; last observation: {last!r}"
    )


def _client_error(fn) -> dict:
    """Return the botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}"
    )


def _create_cmk(ctx) -> dict[str, str]:
    """A tagged, symmetric customer-managed CMK with the default key policy."""
    kms = ctx.client("kms")
    meta = kms.create_key(
        Description=f"sim2real behavioral {CHECK}",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[
            {"TagKey": "sim2real", "TagValue": "behavioral"},
            {"TagKey": "sim2real-check", "TagValue": CHECK},
        ],
    )["KeyMetadata"]
    key_id = meta["KeyId"]
    # 7 days is the KMS minimum pending window; the key cannot be deleted faster than that.
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return {"id": key_id, "arn": meta["Arn"]}


def _create_active_stream(ctx, *, shard_count: int = 1) -> dict[str, str]:
    """Create-or-adopt a provisioned stream, tagged, and wait until it is ACTIVE."""
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kds-")
    try:
        kinesis.create_stream(
            StreamName=name,
            ShardCount=shard_count,
            StreamModeDetails={"StreamMode": "PROVISIONED"},
            Tags={"sim2real": "behavioral", "sim2real-check": CHECK},
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceInUseException":
            raise
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    )
    summary = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=240.0,
        interval_s=3.0,
        description=f"stream {name} to reach ACTIVE",
    )
    return {"name": name, "arn": summary["StreamARN"]}


def _single_shard_id(ctx, stream_name: str) -> str:
    """ListShards can lag ACTIVE briefly; poll until exactly one shard is addressable."""
    kinesis = ctx.client("kinesis")

    def probe() -> list:
        try:
            return kinesis.list_shards(StreamName=stream_name)["Shards"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ResourceInUseException", "ResourceNotFoundException"):
                return []
            raise

    shards = _poll_until(
        probe,
        lambda s: len(s) == 1,
        timeout_s=90.0,
        interval_s=3.0,
        description=f"exactly one shard to be addressable on {stream_name}",
    )
    return shards[0]["ShardId"]


def _put_or_none(kinesis, stream_name: str, payload: bytes) -> str | None:
    """The new SequenceNumber, or None while the CMK-derived refusal is still in force."""
    try:
        return kinesis.put_record(
            StreamName=stream_name, Data=payload, PartitionKey=_PARTITION_KEY
        )["SequenceNumber"]
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code and code.startswith("KMS"):
            return None
        raise


def _read_records(ctx, stream_name: str, shard_id: str, *, expect: int) -> list[dict]:
    """Read the shard from TRIM_HORIZON with a FRESH iterator; return every record read."""
    kinesis = ctx.client("kinesis")
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )["ShardIterator"]
    collected: list[dict] = []
    state = {"iterator": iterator}

    def probe() -> int:
        resp = kinesis.get_records(ShardIterator=state["iterator"], Limit=1000)
        collected.extend(resp["Records"])
        state["iterator"] = resp.get("NextShardIterator") or state["iterator"]
        return len(collected)

    _poll_until(
        probe,
        lambda n: n >= expect,
        timeout_s=90.0,
        interval_s=1.0,
        description=f"{expect} records to be readable from {shard_id}",
    )
    return collected


def _read_refused(ctx, stream_name: str, shard_id: str, refusal: dict) -> bool:
    """True once GetRecords is refused, with the error kept in ``refusal``."""
    kinesis = ctx.client("kinesis")
    try:
        iterator = kinesis.get_shard_iterator(
            StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
        )["ShardIterator"]
        kinesis.get_records(ShardIterator=iterator, Limit=1000)
    except ClientError as exc:
        refusal.update(exc.response.get("Error", {}))
        return True
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
