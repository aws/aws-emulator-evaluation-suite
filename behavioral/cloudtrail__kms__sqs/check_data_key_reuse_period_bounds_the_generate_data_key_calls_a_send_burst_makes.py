"""data-key-reuse-period-bounds-the-generate-data-key-calls-a-send-burst-makes."""

# What the check relies on, each a claim about real AWS that its assertions test:
#   - `KmsDataKeyReusePeriodSeconds` bounds how long SQS reuses one cached data key before calling
#     kms:GenerateDataKey again ("A shorter time period provides better security but results in
#     more calls to AWS KMS"; API minimum 60, maximum 86400), so sends inside ONE window produce
#     exactly one GenerateDataKey and sends spanning two windows produce more.
#   - The GenerateDataKey record's `requestParameters.encryptionContext` names the queue at the key
#     `aws:sqs:arn` (SQS DeveloperGuide, encryption context); this join attributes a KMS call to a
#     queue, so it is asserted exactly, never relaxed to a whole-record substring.
#   - The GenerateDataKey call SQS makes on the caller's behalf is attributed to the CALLER's
#     identity with `userIdentity.invokedBy == "sqs.amazonaws.com"` (CloudTrail userIdentity
#     element); the caller's own CreateQueue record is the twin control for that identity.
#   - GenerateDataKey is a KMS management event, visible in event history via LookupEvents with no
#     trail.
#   - The count is `== 1` on the long-window queue and `>= 2` on the short-window queue: the exact
#     short-queue number is undocumented, the documented consequence is one-sided.
#   - Both queues use the SAME customer CMK, so the encryption context alone separates their KMS
#     traffic.
#   - CloudTrail indexes each call independently, so the count must hold across `_STABLE_POLLS`
#     consecutive reads before it is trusted; regional management events index within minutes.
#   - The wait between the short queue's two send batches is a real margin past the 60 s minimum:
#     a cache expiring inside SQS has no observable to poll, so CloudTrail is the only side channel.
#   - Teardown leaves ONE CMK in a 7-day pending-deletion window (reversible via
#     CancelKeyDeletion), because a KMS key has no immediate delete.
#   - Wall clock: ~60 s setup + 150 s window wait + 255 s index poll + teardown.

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "data-key-reuse-period-bounds-the-generate-data-key-calls-a-send-burst-makes"
GROUP = "eventing"
SERVICES = ["cloudtrail", "kms", "sqs"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# 60 is the API MINIMUM. The long window must comfortably outlast the whole burst.
_SHORT_REUSE_S = 60
_LONG_REUSE_S = 3600
# A real margin past the minimum, not a bare second: real send/encrypt latency inside SQS can
# eat into a thin margin before the second batch is even sent.
_WINDOW_ROLLOVER_WAIT_S = 150.0
_SENDS_PER_BATCH = 3
_INDEX_BUDGET_S = 255.0
_TOTAL_WAIT_BUDGET_S = _INDEX_BUDGET_S + _WINDOW_ROLLOVER_WAIT_S + 120.0
_POLL_INTERVAL_S = 10.0
_STABLE_POLLS = 3  # freeze detector: the count must hold across this many consecutive reads
_PAGE_CEILING = 40
_PENDING_DELETION_DAYS = 7

# ===== helpers =====


def _lookup_all(ct, **kw):
    out = []
    nxt = None
    for _ in range(_PAGE_CEILING):
        if nxt:
            kw["NextToken"] = nxt
        else:
            kw.pop("NextToken", None)
        resp = ct.lookup_events(**kw)
        out.extend(resp["Events"])
        nxt = resp.get("NextToken")
        if not nxt:
            return out
    raise AssertionError(
        f"{DATAPLANE_MARKER}: LookupEvents paged past {_PAGE_CEILING} pages without exhausting; "
        "a COUNT asserted over a truncated result would be meaningless"
    )


def _generate_data_key_records(ct):
    return [
        json.loads(e["CloudTrailEvent"])
        for e in _lookup_all(
            ct,
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": "GenerateDataKey"}
            ],
        )
    ]


def _for_queue(records, queue_arn):
    """Records whose encryptionContext names this queue; the key is asserted separately below."""
    out = []
    for r in records:
        ctx_map = (r.get("requestParameters") or {}).get("encryptionContext") or {}
        if ctx_map.get("aws:sqs:arn") == queue_arn:
            out.append(r)
    return out


def _create_queue_record(ct, queue_name):
    """The caller's own CreateQueue record naming ``queue_name``, or ``None`` if not yet indexed.

    The twin control: a call the caller made directly, to compare its real `userIdentity` against
    the GenerateDataKey records SQS makes on the caller's behalf.
    """
    for r in _lookup_all(
        ct, LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "CreateQueue"}]
    ):
        rec = json.loads(r["CloudTrailEvent"])
        if queue_name in json.dumps(rec.get("requestParameters") or {}):
            return rec
    return None


def _create_cmk(ctx):
    kms = ctx.client("kms")
    key = kms.create_key(
        Description=f"{CHECK} symmetric CMK",
        KeyUsage="ENCRYPT_DECRYPT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    # A KMS key has no immediate delete; the schedule is reversible.
    ctx.on_cleanup(
        lambda: kms.schedule_key_deletion(
            KeyId=key_id, PendingWindowInDays=_PENDING_DELETION_DAYS
        )
    )
    kms.put_key_policy(
        KeyId=key_id,
        PolicyName="default",
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Id": "simparity-sqs-cmk",
                "Statement": [
                    {
                        "Sid": "EnableRoot",
                        "Effect": "Allow",
                        "Principal": {
                            "AWS": f"arn:aws:iam::{ctx.client('sts').get_caller_identity()['Account']}:root"
                        },
                        "Action": "kms:*",
                        "Resource": "*",
                    },
                    {
                        "Sid": "AllowSqs",
                        "Effect": "Allow",
                        "Principal": {"Service": "sqs.amazonaws.com"},
                        "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
                        "Resource": "*",
                    },
                ],
            }
        ),
    )
    return key_id, key["Arn"]


def _create_encrypted_queue(ctx, key_id, reuse_s, label):
    sqs = ctx.client("sqs")
    name = ctx.unique_name(f"simparity-ctkms-{label}-")
    url = sqs.create_queue(
        QueueName=name,
        Attributes={
            "KmsMasterKeyId": key_id,
            "KmsDataKeyReusePeriodSeconds": str(reuse_s),
        },
        tags={"sim2real": CHECK, "simparity-role": label},
    )["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_quietly(sqs, url))
    attrs = sqs.get_queue_attributes(
        QueueUrl=url,
        AttributeNames=["QueueArn", "KmsDataKeyReusePeriodSeconds", "KmsMasterKeyId"],
    )["Attributes"]
    assert attrs["KmsDataKeyReusePeriodSeconds"] == str(reuse_s), (
        f"[{label}] the reuse period must round-trip: expected {reuse_s!r}, actual "
        f"{attrs['KmsDataKeyReusePeriodSeconds']!r}"
    )
    assert attrs.get("SqsManagedSseEnabled") in (None, "false"), (
        f"[{label}] KmsMasterKeyId and SqsManagedSseEnabled are mutually exclusive; a queue with a "
        f"CMK must not also report SQS-managed SSE: expected absent/'false', actual "
        f"{attrs.get('SqsManagedSseEnabled')!r}"
    )
    return url, attrs["QueueArn"], name


def _delete_queue_quietly(sqs, url):
    try:
        sqs.delete_queue(QueueUrl=url)
    except ClientError as exc:
        if "NonExistentQueue" not in str(exc.response.get("Error", {}).get("Code", "")):
            raise


def _send_batch(sqs, url, label, batch):
    """Sends, and PROVES each send happened by requiring a MessageId back."""
    ids = []
    for i in range(_SENDS_PER_BATCH):
        resp = sqs.send_message(QueueUrl=url, MessageBody=f"{CHECK}:{label}:{batch}:{i}")
        assert resp.get("MessageId"), (
            f"[{label}] send {batch}.{i} must return a MessageId, otherwise the burst this check "
            f"counts against never happened: expected a non-empty id, actual {resp.get('MessageId')!r}"
        )
        ids.append(resp["MessageId"])
    return ids


# timing:real-time — ttl: 60 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html
@tags("axis:happy-path", "cap:c4", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A queue's data-key reuse period bounds how often SQS calls KMS: six sends make exactly one
    GenerateDataKey under a 3600 s period and at least two across a 60 s boundary, each attributed to
    the caller with invokedBy sqs.amazonaws.com and the queue's ARN in its encryption context."""
    sqs = ctx.client("sqs")
    ct = ctx.client("cloudtrail")
    caller_arn = ctx.client("sts").get_caller_identity()["Arn"]

    key_id, key_arn = _create_cmk(ctx)
    long_url, long_arn, long_name = _create_encrypted_queue(ctx, key_id, _LONG_REUSE_S, "long")
    short_url, short_arn, short_name = _create_encrypted_queue(ctx, key_id, _SHORT_REUSE_S, "short")
    assert long_arn != short_arn, (
        "the two queues must be distinct for the count to be attributable: actual both "
        f"{long_arn!r}"
    )

    # ---- the burst. The long queue's six sends are contiguous, inside one 3600 s window. ----------
    _send_batch(sqs, long_url, "long", 0)
    _send_batch(sqs, long_url, "long", 1)

    # ---- the short queue's six sends straddle a 60 s boundary with a real margin. -----------------
    _send_batch(sqs, short_url, "short", 0)
    time.sleep(_WINDOW_ROLLOVER_WAIT_S)
    _send_batch(sqs, short_url, "short", 1)

    # ---- terminal read at CloudTrail, via an operation neither SQS nor KMS was asked for. --------
    # CloudTrail's indexing is eventually consistent PER EVENT, not atomic: a target that makes two
    # GenerateDataKey calls can have the first indexed while the second is still invisible. Stopping
    # at the first sighting of >=1 per queue would misread "not yet indexed" as "only ever made one" --
    # a freeze detector is required: the signature must hold across _STABLE_POLLS consecutive
    # reads before the count is trusted, not just the first time the minimums are met.
    deadline = time.monotonic() + _INDEX_BUDGET_S
    records = []
    caller_record = None
    prev_signature = None
    stable_polls = 0
    while True:
        records = _generate_data_key_records(ct)
        if caller_record is None:
            caller_record = _create_queue_record(ct, long_name)
        long_calls = _for_queue(records, long_arn)
        short_calls = _for_queue(records, short_arn)
        minimums_met = bool(long_calls) and bool(short_calls) and caller_record is not None
        signature = (len(long_calls), len(short_calls), caller_record is not None)
        stable_polls = stable_polls + 1 if signature == prev_signature else 0
        prev_signature = signature
        # The short queue's second call may be indexed well after its first, so the loop waits for
        # it; at the deadline a short queue STABLE at one call goes to the count assertions below,
        # which name that failure, and counts still moving fail here.
        if minimums_met and len(short_calls) >= 2 and stable_polls >= _STABLE_POLLS:
            break
        if time.monotonic() >= deadline:
            if minimums_met and stable_polls >= _STABLE_POLLS:
                break
            # Every record seen but the counts still moving is CloudTrail indexing, not a missing
            # data plane, so it fails without the marker.
            assert not minimums_met, (
                f"GenerateDataKey counts must hold across {_STABLE_POLLS} consecutive reads "
                f"within {_INDEX_BUDGET_S:.0f}s: expected a stable count, actual "
                f"{len(long_calls)} for the long queue and {len(short_calls)} for the short one, "
                "still changing at the deadline"
            )
            raise AssertionError(
                f"{DATAPLANE_MARKER}: GenerateDataKey records for both queues, or the long queue's "
                f"own CreateQueue record, were not indexed and stable within {_INDEX_BUDGET_S:.0f}s; "
                f"expected >=1 GenerateDataKey each and 1 CreateQueue, stable across "
                f"{_STABLE_POLLS} consecutive reads, actual {len(long_calls)} for the long queue and "
                f"{len(short_calls)} for the short one, out of {len(records)} GenerateDataKey "
                f"records examined, CreateQueue record {'found' if caller_record else 'missing'}. A "
                "target that never calls KMS on the send path, or that supplies no encryption "
                "context, fails here."
            )
        time.sleep(_POLL_INTERVAL_S)

    long_calls = _for_queue(records, long_arn)
    short_calls = _for_queue(records, short_arn)

    # The twin control: the caller's own identity on a call it made directly, so the
    # GenerateDataKey records below are compared against a MEASURED identity, not a guessed literal.
    caller_ident = caller_record.get("userIdentity") or {}
    assert caller_ident.get("arn") == caller_arn, (
        "the caller's own CreateQueue must be attributed to the caller: expected "
        f"{caller_arn!r}, actual {caller_ident.get('arn')!r}"
    )
    assert caller_ident.get("type") != "AWSService", (
        "the caller's own call must NOT be attributed to a service principal -- this is the twin "
        f"control for the GenerateDataKey attribution below: expected anything but 'AWSService', "
        f"actual {caller_ident.get('type')!r}"
    )
    assert "invokedBy" not in caller_ident, (
        "a call the caller made directly must carry no invokedBy: expected the key absent, actual "
        f"{caller_ident.get('invokedBy')!r}"
    )

    # The COUNT -- the whole point.
    assert len(long_calls) == 1, (
        f"a {_LONG_REUSE_S}s reuse period must let {2 * _SENDS_PER_BATCH} contiguous sends share ONE "
        f"data key: expected exactly 1 GenerateDataKey naming {long_arn}, actual "
        f"{len(long_calls)}. A target that calls KMS per send produces {2 * _SENDS_PER_BATCH}."
    )
    assert len(short_calls) >= 2, (
        f"a {_SHORT_REUSE_S}s reuse period must force a REFRESH once the burst straddles the window "
        f"({_WINDOW_ROLLOVER_WAIT_S:.0f}s apart): expected >=2 GenerateDataKey naming {short_arn}, "
        f"actual {len(short_calls)}. A target that caches forever produces 1 and passes the long-"
        "queue leg -- this is the twin control that catches it."
    )
    assert len(short_calls) > len(long_calls), (
        "the documented consequence is one-sided -- a shorter period 'results in more calls to AWS "
        f"KMS' -- so the short queue must have made strictly more: expected "
        f"{len(short_calls)} > {len(long_calls)}, actual not"
    )

    # Attribution: the caller's own identity, with invokedBy naming the service, and the key.
    for label, calls, arn in (("long", long_calls, long_arn), ("short", short_calls, short_arn)):
        for rec in calls:
            ident = rec.get("userIdentity") or {}
            assert ident.get("type") == caller_ident.get("type"), (
                f"[{label}] a KMS call SQS made on the caller's behalf is attributed to the "
                f"caller's own identity: expected userIdentity.type {caller_ident.get('type')!r}, "
                f"actual {ident.get('type')!r}"
            )
            assert ident.get("arn") == caller_arn, (
                f"[{label}] userIdentity.arn: expected the caller's own {caller_arn!r}, actual "
                f"{ident.get('arn')!r}"
            )
            assert ident.get("invokedBy") == "sqs.amazonaws.com", (
                f"[{label}] userIdentity.invokedBy: expected 'sqs.amazonaws.com', actual "
                f"{ident.get('invokedBy')!r}"
            )
            assert rec.get("eventSource") == "kms.amazonaws.com", (
                f"[{label}] eventSource: expected 'kms.amazonaws.com', actual "
                f"{rec.get('eventSource')!r}"
            )
            ctx_map = (rec.get("requestParameters") or {}).get("encryptionContext") or {}
            assert ctx_map.get("aws:sqs:arn") == arn, (
                f"[{label}] requestParameters.encryptionContext must name the queue at key "
                f"'aws:sqs:arn': expected {arn!r}, actual {ctx_map.get('aws:sqs:arn')!r}; full "
                f"context {ctx_map!r}"
            )
            assert key_arn in json.dumps(rec.get("resources") or []) or key_id in json.dumps(
                rec.get("requestParameters") or {}
            ), (
                f"[{label}] the record must name the CMK the queues share: expected {key_arn!r} "
                f"among resources {rec.get('resources')!r} or {key_id!r} in requestParameters "
                f"{rec.get('requestParameters')!r}, actual neither"
            )
            assert "plaintext" not in json.dumps(rec).lower(), (
                f"[{label}] a GenerateDataKey record must never carry key material: expected no "
                "'plaintext' anywhere in the record, actual present"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
