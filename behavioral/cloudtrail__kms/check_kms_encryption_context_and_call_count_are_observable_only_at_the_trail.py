"""kms-encryption-context-and-call-count-are-observable-only-at-the-trail."""

# The claims run() asserts:
#   H1  kms:Encrypt is audited with requestParameters.encryptionContext equal, as a MAP, to the
#       EncryptionContext the caller supplied. Key casing (lower camel `encryptionContext`) is
#       taken from the KMS CloudTrail examples; if it differs, correct the key, do NOT relax the
#       comparison to a substring.
#   H2  GetKeyLastUsage's KeyLastUsage.CloudTrailEventId is the CloudTrail `eventID` of the last
#       successful cryptographic operation, and LookupEvents returns an event with exactly that
#       EventId. Source: the Smithy model,
#       com.amazonaws.kms#KeyLastUsageData$CloudTrailEventId -- "The CloudTrail eventId
#       associated with the last successful cryptographic operation."
#   H3  KeyLastUsage.KmsRequestId is the request id botocore saw on the Encrypt response, and the
#       CloudTrail record's `requestID` is the same string. A three-way identity across two
#       services and one SDK response.
#   H4  KMS never logs key material: neither the plaintext nor the ciphertext appears in the
#       delivered record.
#   H5  EXACT COUNT. Four Encrypt calls against one key produce exactly four Encrypt records
#       naming that key in the window, with four distinct EventIds; a sibling key used zero times
#       produces exactly zero. The KMS API cannot express this at all --
#       GetKeyLastUsageResponse has members KeyId, KeyLastUsage, TrackingStartDate and
#       KeyCreationDate and NO counter of any kind (verified in the Smithy model), so CloudTrail
#       is the only side-channel there is.
#   H6  KMS last-usage tracking is eventually consistent; AWS documents up to an hour of delay.
#   H7  Index latency 80-136 s measured for cloudtrail; budget 255 s from the first lookup.
#   H8  Teardown: a KMS key cannot be deleted immediately. ScheduleKeyDeletion with the 7-day
#       minimum is used, which is what the shipped kms checks do.

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kms-encryption-context-and-call-count-are-observable-only-at-the-trail"
GROUP = "eventing"
SERVICES = ["cloudtrail", "kms"]

# A data-plane FAIL marker.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_INDEX_BUDGET_S = 255.0  # H7
_POLL_INTERVAL_S = 2.0
_LAST_USAGE_BUDGET_S = 1500.0  # H6
_LAST_USAGE_INTERVAL_S = 30.0
_PAGE_CEILING = 40
_PENDING_WINDOW_DAYS = 7  # H8: the documented minimum for ScheduleKeyDeletion.

_EXTRA_ENCRYPTS = 3  # plus the first one == 4 total


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded)."""
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
    return out


def _encrypt_events(ct, *, start, end):
    return _lookup_all(
        ct, StartTime=start, EndTime=end, MaxResults=50,
        LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": "Encrypt"}],
    )


def _naming(events, needle):
    return [ev for ev in events if needle in ev.get("CloudTrailEvent", "")]


def _schedule_key_deletion(kms, key_id):
    """Idempotent teardown for exactly the key this check created. A KMS key has no immediate
    delete; the 7-day pending window is the minimum real AWS accepts."""
    try:
        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=_PENDING_WINDOW_DAYS)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        # Already scheduled, or already gone: both are the desired end state.
        if code not in ("KMSInvalidStateException", "NotFoundException"):
            raise


@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c2")
def run(ctx) -> None:
    """An Encrypt's EncryptionContext appears as an equal map in the CloudTrail record that
    GetKeyLastUsage's CloudTrailEventId names, and a key used four times has exactly four Encrypt
    records while an unused twin key has none: the KMS API itself exposes neither fact."""
    ct = ctx.client("cloudtrail")
    kms = ctx.client("kms")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # --- The key under test, and the twin control key, created in the same instant.
    used_key = kms.create_key(
        Description=f"sim2real-behav {CHECK} (used)",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: _schedule_key_deletion(kms, used_key["KeyId"]))
    unused_key = kms.create_key(
        Description=f"sim2real-behav {CHECK} (control, never used)",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    ctx.on_cleanup(lambda: _schedule_key_deletion(kms, unused_key["KeyId"]))
    used_key_id = used_key["KeyId"]
    used_key_arn = used_key["Arn"]
    unused_key_id = unused_key["KeyId"]
    assert used_key_id != unused_key_id, (
        f"CreateKey returned the same KeyId twice ({used_key_id!r}); the control key must be a "
        f"different key"
    )

    context_token = ctx.unique_name("sim2realkmsctx").lower()
    encryption_context = {
        "sim2real-check": CHECK,
        "sim2real-token": context_token,
        "sim2real-account": account,
    }
    plaintext = f"sim2real-behav-{context_token}".encode()

    emitted_at = datetime.datetime.now(datetime.timezone.utc)

    # Three calls, each distinguishable, so the count below is about calls and not about one call
    # observed several times. They come first: GetKeyLastUsage names the LAST operation.
    extra_tokens = []
    for _ in range(_EXTRA_ENCRYPTS):
        extra = ctx.unique_name("sim2realkmsctxn").lower()
        extra_tokens.append(extra)
        kms.encrypt(
            KeyId=used_key_id,
            Plaintext=plaintext,
            EncryptionContext={"sim2real-check": CHECK, "sim2real-token": extra},
        )
    total_encrypts = 1 + _EXTRA_ENCRYPTS

    last = kms.encrypt(
        KeyId=used_key_id, Plaintext=plaintext, EncryptionContext=encryption_context
    )
    sdk_request_id = last["ResponseMetadata"]["RequestId"]
    ciphertext = last["CiphertextBlob"]
    assert sdk_request_id, (
        "the Encrypt response carried no ResponseMetadata.RequestId, so there is nothing to "
        "correlate KMS's own KmsRequestId and CloudTrail's requestID against"
    )

    # --- KMS's own account of its last usage. Bounded poll; RAISES on expiry.
    last_usage = None
    candidate = None
    usage_polls = 0
    usage_t0 = time.monotonic()
    while time.monotonic() - usage_t0 < _LAST_USAGE_BUDGET_S:
        usage_polls += 1
        candidate = kms.get_key_last_usage(KeyId=used_key_id).get("KeyLastUsage", {})
        if candidate.get("KmsRequestId") == sdk_request_id and candidate.get("CloudTrailEventId"):
            last_usage = candidate
            break
        time.sleep(_LAST_USAGE_INTERVAL_S)
    assert last_usage is not None, (
        f"GetKeyLastUsage never reported a CloudTrailEventId for the last Encrypt (request id "
        f"{sdk_request_id!r}) on key {used_key_id!r} within {_LAST_USAGE_BUDGET_S}s over "
        f"{usage_polls} polls, after {total_encrypts} successful Encrypt calls starting at "
        f"{emitted_at.isoformat()}; last answer {candidate!r}. The member is the only handle KMS "
        f"gives a caller onto the audit record of its own cryptographic operation"
    )
    assert last_usage["Operation"] == "Encrypt", (
        f"KeyLastUsage.Operation is {last_usage.get('Operation')!r}, expected 'Encrypt' -- the "
        f"only kind of cryptographic operation this key has ever been used for"
    )
    assert last_usage["KmsRequestId"], (
        f"KeyLastUsage.KmsRequestId is {last_usage.get('KmsRequestId')!r}; the model documents it "
        f"as the request id of the last successful cryptographic operation"
    )
    cloudtrail_event_id = last_usage["CloudTrailEventId"]

    # --- Follow KMS's event id into CloudTrail. Bounded poll; RAISES on expiry.
    envelope = None
    polls = 0
    scanned = 0
    t0 = time.monotonic()
    while time.monotonic() - t0 < _INDEX_BUDGET_S:
        polls += 1
        window_end = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
        events = _encrypt_events(
            ct, start=emitted_at - datetime.timedelta(minutes=2), end=window_end
        )
        scanned = len(events)
        for ev in events:
            if ev["EventId"] == cloudtrail_event_id:
                envelope = ev
                break
        if envelope is not None:
            break
        time.sleep(_POLL_INTERVAL_S)
    waited = time.monotonic() - t0

    assert envelope is not None, (
        f"{DATAPLANE_MARKER}: KMS reports that its last cryptographic operation on key "
        f"{used_key_id!r} is CloudTrail event {cloudtrail_event_id!r}, but LookupEvents does not "
        f"have it: {polls} polls over {waited:.0f}s scanned {scanned} Encrypt events and none "
        f"carried that EventId. Two services disagree about an event one of them named. Either "
        f"CloudTrail did not audit the operation, or KMS invented the id"
    )
    record = json.loads(envelope["CloudTrailEvent"])
    assert record["eventID"] == cloudtrail_event_id, (
        f"the envelope was selected by EventId {cloudtrail_event_id!r} but the embedded record's "
        f"eventID is {record.get('eventID')!r}"
    )
    assert record["eventSource"] == "kms.amazonaws.com", (
        f"eventSource is {record.get('eventSource')!r}, expected kms.amazonaws.com"
    )
    assert record["eventName"] == "Encrypt", (
        f"eventName is {record.get('eventName')!r}, expected Encrypt"
    )
    # CloudTrail classifies KMS cryptographic operations, Encrypt included, as read-only events.
    assert record["readOnly"] is True, (
        f"readOnly is {record.get('readOnly')!r} for kms:Encrypt"
    )

    # --- H1: the encryption context, as a map, byte-for-byte.
    parameters = record["requestParameters"]
    assert parameters is not None, (
        f"requestParameters is null on a SUCCESSFUL kms:Encrypt (event {cloudtrail_event_id!r}); "
        f"real AWS records the arguments of an accepted call"
    )
    assert "encryptionContext" in parameters, (
        f"requestParameters has no encryptionContext member: {sorted(parameters)!r}. The context "
        f"is the one part of a KMS request a security team can actually query CloudTrail for, and "
        f"the whole point of supplying it"
    )
    assert parameters["encryptionContext"] == encryption_context, (
        f"requestParameters.encryptionContext is {parameters['encryptionContext']!r}, expected the "
        f"map this check supplied ({encryption_context!r}). It must be a MAP with the same keys "
        f"and the same values -- not a serialised string, not a subset, not the keys with the "
        f"values elided"
    )
    assert used_key_id in json.dumps(parameters) or used_key_arn in json.dumps(parameters), (
        f"requestParameters {parameters!r} names neither the key id ({used_key_id!r}) nor its ARN "
        f"({used_key_arn!r}), so the record does not say which key was used"
    )

    # --- H3: three identifiers, one request.
    assert last_usage["KmsRequestId"] == sdk_request_id, (
        f"KeyLastUsage.KmsRequestId is {last_usage['KmsRequestId']!r} but botocore observed "
        f"{sdk_request_id!r} on the Encrypt response. One request id is minted once"
    )
    assert record["requestID"] == sdk_request_id, (
        f"the CloudTrail record's requestID is {record.get('requestID')!r}, expected the request "
        f"id botocore observed on the Encrypt call ({sdk_request_id!r}). 'Find the audit record "
        f"for this call' is exactly this join, and a target that mints ids per response cannot "
        f"make the two equal"
    )

    # --- H4: no key material anywhere in the record.
    raw = envelope["CloudTrailEvent"]
    assert plaintext.decode() not in raw, (
        f"the plaintext this check encrypted appears in the delivered CloudTrail record for event "
        f"{cloudtrail_event_id!r}. KMS must never log key material; a customer's CloudTrail "
        f"retention and access posture assumes it does not"
    )
    assert ciphertext.decode("latin-1") not in raw, (
        f"the ciphertext blob Encrypt returned appears in the delivered CloudTrail record for "
        f"event {cloudtrail_event_id!r}; the record describes the request, not its payload"
    )

    # --- H5: the exact count, and the twin control. A CLOSED window, so both numbers are about
    # the same immutable interval and the index is demonstrably past it (the event KMS named was
    # found above).
    count_end = datetime.datetime.now(datetime.timezone.utc)
    window = _encrypt_events(
        ct, start=emitted_at - datetime.timedelta(minutes=2), end=count_end
    )
    mine = _naming(window, used_key_id) or _naming(window, used_key_arn)
    assert len(mine) == total_encrypts, (
        f"this check made exactly {total_encrypts} kms:Encrypt calls against key {used_key_id!r} "
        f"and CloudTrail reports {len(mine)} Encrypt events naming it: "
        f"{[ev.get('EventId') for ev in mine]!r}. The KMS API cannot express this number at all "
        f"-- GetKeyLastUsageResponse has no counter -- so the trail is the only place a per-key "
        f"call count exists. A target that emits one record per KEY rather than per CALL, or that "
        f"batches or de-duplicates records, lands here"
    )
    assert len({ev["EventId"] for ev in mine}) == total_encrypts, (
        f"the {len(mine)} Encrypt events naming key {used_key_id!r} carry only "
        f"{len({ev['EventId'] for ev in mine})} distinct EventIds: "
        f"{[ev.get('EventId') for ev in mine]!r}. Each call is its own event"
    )
    found_tokens = set()
    for ev in mine:
        body = ev["CloudTrailEvent"]
        for token in [context_token, *extra_tokens]:
            if token in body:
                found_tokens.add(token)
    assert found_tokens == {context_token, *extra_tokens}, (
        f"each of the {total_encrypts} calls supplied a DIFFERENT encryption-context token, so "
        f"each must be visible in its own record. Missing: "
        f"{sorted({context_token, *extra_tokens} - found_tokens)!r}. A target that records the "
        f"right NUMBER of events but the same context on all of them fails here"
    )

    unused_usage = kms.get_key_last_usage(KeyId=unused_key_id).get("KeyLastUsage", {})
    assert "Timestamp" not in unused_usage, (
        f"the control key {unused_key_id!r} has never been used for a cryptographic operation, "
        f"but GetKeyLastUsage reports Timestamp {unused_usage.get('Timestamp')!r}. The member is "
        f"absent until the key is used"
    )
    assert "CloudTrailEventId" not in unused_usage, (
        f"the control key {unused_key_id!r} has never been used, but GetKeyLastUsage reports "
        f"CloudTrailEventId {unused_usage.get('CloudTrailEventId')!r}"
    )
    control_events = _naming(window, unused_key_id)
    assert control_events == [], (
        f"the control key {unused_key_id!r} was created in the same instant as {used_key_id!r} "
        f"and never used, yet CloudTrail reports {len(control_events)} Encrypt event(s) naming "
        f"it: {[ev.get('EventId') for ev in control_events]!r}. This zero is what makes the "
        f"{total_encrypts} above a measurement rather than a coincidence -- a target that "
        f"attributes every Encrypt in the window to every key it knows about fails here"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
