"""write-only-read-write-type-delivers-the-put-and-withholds-the-get."""

# ReadWriteType "WriteOnly" on a basic S3 data-event selector delivers PutObject and withholds
# GetObject; widening it to "All" then delivers an identical GetObject, which separates "withheld
# by the selector" from "no data events at all". A later PutObject on the same wiring is the
# barrier for the absence. Data events are delivered about every 5 minutes, so each window is 600 s.

from __future__ import annotations

import gzip
import io
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "write-only-read-write-type-delivers-the-put-and-withholds-the-get"
GROUP = "eventing"
SERVICES = ["cloudtrail", "s3"]

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

_DELIVERY_BUDGET_S = 600.0  # per window
_SECOND_WINDOW_BUDGET_S = 600.0
# The ceiling on the 1x-measured-latency hold, so the worst-case total wait stays under 1800 s:
# 600 window1 + 300 hold + 120 selector + 600 window2 = 1620.
_HOLD_CAP_S = 300.0
_SELECTOR_BUDGET_S = 120.0
_CLEANUP_BUDGET_S = 240.0  # the log bucket keeps receiving writes after StopLogging
_POLL_INTERVAL_S = 2.0
_ROUND_INTERVAL_S = 30.0  # spacing between repeated call rounds, not a poll interval

# ===== helpers =====


def _create_bucket(ctx, prefix):
    s3 = ctx.client("s3")
    name = ctx.unique_name(prefix)
    kw = {"Bucket": name}
    if ctx.region != "us-east-1":
        kw["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kw)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _attach_trail_policy(ctx, bucket, account_id):
    ctx.client("s3").put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{bucket}",
                    },
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudtrail.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                        "Condition": {
                            "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                        },
                    },
                ],
            }
        ),
    )


def _drain_and_delete_bucket(s3, bucket):
    """RAISES on a deadline miss so a leak is visible rather than silent."""
    deadline = time.monotonic() + _CLEANUP_BUDGET_S
    while True:
        keys = []
        token = None
        while True:
            kw = {"Bucket": bucket, "MaxKeys": 1000}
            if token:
                kw["ContinuationToken"] = token
            page = s3.list_objects_v2(**kw)
            keys.extend(o["Key"] for o in page.get("Contents", []))
            token = page.get("NextContinuationToken")
            if not token:
                break
        for i in range(0, len(keys), 1000):
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": k} for k in keys[i : i + 1000]]}
            )
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"bucket {bucket} still not empty after {_CLEANUP_BUDGET_S:.0f}s; LEAKING -- report "
                "the bucket name"
            )
        time.sleep(10.0)


def _delivered_records(s3, bucket):
    """Every record in every delivered gzipped log file. The terminal read."""
    out = []
    token = None
    keys = []
    while True:
        kw = {"Bucket": bucket, "Prefix": "AWSLogs/", "MaxKeys": 1000}
        if token:
            kw["ContinuationToken"] = token
        page = s3.list_objects_v2(**kw)
        keys.extend(o["Key"] for o in page.get("Contents", []))
        token = page.get("NextContinuationToken")
        if not token:
            break
    for key in keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        if not body:
            # Alongside the real .json.gz log files, the trail's own S3 write leaves a benign
            # zero-byte "directory marker" object at the bare prefix (e.g.
            # "AWSLogs/<account>/CloudTrail/", no filename, no content) -- not a log file, and gzip
            # on an empty body decompresses to b"" rather than raising, so it must be skipped
            # explicitly or json.loads("") raises on every delivery poll.
            continue
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as fh:
            out.extend(json.loads(fh.read().decode("utf-8")).get("Records", []))
    return out


def _for_key(records, event_name, object_key):
    return [
        r
        for r in records
        if r.get("eventName") == event_name
        and object_key in json.dumps(r.get("requestParameters") or {})
    ]


def _selectors(read_write_type, data_bucket):
    return [
        {
            "ReadWriteType": read_write_type,
            "IncludeManagementEvents": True,
            "DataResources": [
                {"Type": "AWS::S3::Object", "Values": [f"arn:aws:s3:::{data_bucket}/"]}
            ],
        }
    ]


def _expected_echo(selectors):
    """What Put/GetEventSelectors echo back: each selector plus AWS's own default for every field
    the submission left unset (an empty `ExcludeManagementEventSources` list)."""
    return [{**s, "ExcludeManagementEventSources": []} for s in selectors]


def _stop_logging_quietly(ct, trail_arn):
    try:
        ct.stop_logging(Name=trail_arn)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "TrailNotFoundException":
            raise


@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A WriteOnly data-event selector delivers the PutObject and withholds the GetObject, and
    widening it to All delivers an identical read, so the absence is the selector's doing.
    """
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    s3 = ctx.client("s3")
    ct = ctx.client("cloudtrail")

    log_bucket = _create_bucket(ctx, "simparity-ct-s3logs-")
    _attach_trail_policy(ctx, log_bucket, account_id)
    data_bucket = _create_bucket(ctx, "simparity-ct-s3data-")

    trail_name = ctx.unique_name("simparity-ct-s3-")
    trail_arn = ct.create_trail(
        Name=trail_name,
        S3BucketName=log_bucket,
        IsMultiRegionTrail=False,
        IncludeGlobalServiceEvents=False,
        TagsList=[{"Key": "sim2real", "Value": CHECK}],
    )["TrailARN"]
    ctx.on_cleanup(lambda: ct.delete_trail(Name=trail_arn))

    write_only = _selectors("WriteOnly", data_bucket)
    write_only_echo = _expected_echo(write_only)
    put = ct.put_event_selectors(TrailName=trail_arn, EventSelectors=write_only)
    assert put["EventSelectors"] == write_only_echo, (
        "PutEventSelectors must echo the WriteOnly selector plus AWS's own defaults: expected "
        f"{write_only_echo!r}, actual {put['EventSelectors']!r}"
    )

    ct.start_logging(Name=trail_arn)
    ctx.on_cleanup(lambda: _stop_logging_quietly(ct, trail_arn))
    assert ct.get_trail_status(Name=trail_arn).get("IsLogging") is True, (
        "the trail must be logging before the data plane runs: expected True, actual "
        f"{ct.get_trail_status(Name=trail_arn).get('IsLogging')!r}"
    )

    # ---- phase 1: one write, one read, then a second write as the structural barrier --------------
    # Calls issued within seconds of StartLogging or PutEventSelectors are not delivered, and nothing
    # reports when the trail starts capturing, so the sequence repeats on fresh keys every round and
    # the first round whose barrier arrives is the one graded. Every round's GetObject ran under
    # WriteOnly, so none of them may be delivered.
    payload = b"simparity-readwritetype-partition"
    rounds = []
    records = []
    graded = None
    started = time.monotonic()
    deadline = started + _DELIVERY_BUDGET_S
    next_round = started
    while graded is None:
        if time.monotonic() >= next_round:
            r_subject = ctx.unique_name("subject-")
            r_barrier = ctx.unique_name("barrier-")
            s3.put_object(Bucket=data_bucket, Key=r_subject, Body=payload)
            got = s3.get_object(Bucket=data_bucket, Key=r_subject)["Body"].read()
            assert got == payload, (
                "the GetObject under test must genuinely have succeeded, otherwise its absence from "
                f"the trail is meaningless: expected {payload!r}, actual {got!r}"
            )
            s3.put_object(Bucket=data_bucket, Key=r_barrier, Body=payload)
            rounds.append((r_subject, r_barrier, time.monotonic()))
            next_round = time.monotonic() + _ROUND_INTERVAL_S
        time.sleep(_POLL_INTERVAL_S)
        records = _delivered_records(s3, log_bucket)
        for r_subject, r_barrier, r_at in rounds:
            if _for_key(records, "PutObject", r_barrier):
                graded = (r_subject, r_barrier, r_at)
                break
        if graded is None and time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: no barrier PutObject of {len(rounds)} rounds was delivered to "
                f"s3://{log_bucket} within {_DELIVERY_BUDGET_S:.0f}s; expected >=1 record, actual 0 "
                f"of {len(records)} delivered records. A target that delivers no S3 data events at "
                "all fails here, which is why this leg precedes the absence leg."
            )
    subject_key, _, barrier_at = graded
    subject_keys = [r[0] for r in rounds]
    measured_latency_s = time.monotonic() - barrier_at

    # Leg 1: the subject write IS there, with the right classification.
    subject_puts = _for_key(records, "PutObject", subject_key)
    assert subject_puts, (
        f"{DATAPLANE_MARKER}: a WriteOnly selector must deliver PutObject: expected >=1 record "
        f"naming {subject_key}, actual 0 of {len(records)}"
    )
    rec = subject_puts[0]
    assert rec.get("eventSource") == "s3.amazonaws.com", (
        f"eventSource: expected 's3.amazonaws.com', actual {rec.get('eventSource')!r}"
    )
    assert rec.get("eventCategory") == "Data", (
        f"eventCategory: expected 'Data', actual {rec.get('eventCategory')!r}"
    )
    assert rec.get("managementEvent") is False, (
        f"managementEvent: expected False, actual {rec.get('managementEvent')!r}"
    )
    assert rec.get("readOnly") is False, (
        "readOnly must track the OPERATION: PutObject writes, so expected False, actual "
        f"{rec.get('readOnly')!r}"
    )
    assert any(
        r.get("type") == "AWS::S3::Object" and subject_key in (r.get("ARN") or "")
        for r in rec.get("resources") or []
    ), (
        "the record's resources array must name the object as an AWS::S3::Object: expected an entry "
        f"of that type whose ARN contains {subject_key!r}, actual {rec.get('resources')!r}"
    )

    # Leg 2: the read is ABSENT. Barrier landed structurally; hold 1x the measured latency, but
    # poll rather than sleep blind -- a poll catches a stray GetObject that lands mid-window, a
    # bare sleep only catches one that is already there when it wakes.
    hold_s = min(measured_latency_s, _HOLD_CAP_S)
    hold_deadline = time.monotonic() + hold_s
    records = []
    strays = []
    while True:
        records = _delivered_records(s3, log_bucket)
        strays = [x for k in subject_keys for x in _for_key(records, "GetObject", k)]
        if strays or time.monotonic() >= hold_deadline:
            break
        time.sleep(_POLL_INTERVAL_S)
    assert strays == [], (
        "a WriteOnly selector must NOT deliver GetObject: expected 0 GetObject records naming "
        f"any of {subject_keys}, actual {len(strays)}. The barrier PutObject landed in "
        f"{measured_latency_s:.0f}s and a further {hold_s:.0f}s was held (polled, not slept), over "
        f"{len(records)} delivered records, so the data pipeline is demonstrably live. A target "
        "that ignores ReadWriteType fails exactly here."
    )
    # A second independent observable of the same absence.
    assert not [r for r in records if r.get("readOnly") is True and r.get("eventCategory") == "Data"], (
        "under a WriteOnly selector NO delivered data event may be read-only: expected 0 such "
        f"records, actual "
        f"{len([r for r in records if r.get('readOnly') is True and r.get('eventCategory') == 'Data'])}"
    )
    withheld_count = len(records)

    # ---- phase 2, the restore beat: widen the selector and DEMAND the read ------------------------
    all_events = _selectors("All", data_bucket)
    all_events_echo = _expected_echo(all_events)
    ct.put_event_selectors(TrailName=trail_arn, EventSelectors=all_events)
    deadline = time.monotonic() + _SELECTOR_BUDGET_S
    while True:
        current = ct.get_event_selectors(TrailName=trail_arn).get("EventSelectors")
        if current == all_events_echo:
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the widened selector was not readable back within {_SELECTOR_BUDGET_S:.0f}s: "
                f"expected {all_events_echo!r}, actual {current!r}"
            )
        time.sleep(5.0)

    # The widened selector, too, applies only after a lag, so the read repeats on fresh keys.
    reread_keys = []
    found = []
    deadline = time.monotonic() + _SECOND_WINDOW_BUDGET_S
    next_round = time.monotonic()
    while not found:
        if time.monotonic() >= next_round:
            reread_key = ctx.unique_name("reread-")
            s3.put_object(Bucket=data_bucket, Key=reread_key, Body=payload)
            again = s3.get_object(Bucket=data_bucket, Key=reread_key)["Body"].read()
            assert again == payload, (
                f"the restore beat's GetObject must succeed: expected {payload!r}, actual {again!r}"
            )
            reread_keys.append(reread_key)
            next_round = time.monotonic() + _ROUND_INTERVAL_S
        time.sleep(_POLL_INTERVAL_S)
        records = _delivered_records(s3, log_bucket)
        found = [x for k in reread_keys for x in _for_key(records, "GetObject", k)]
        if not found and time.monotonic() >= deadline:
            raise AssertionError(
                f"{DATAPLANE_MARKER}: after widening ReadWriteType to 'All', an identical GetObject "
                f"must be delivered: expected >=1 record naming one of {reread_keys}, actual 0 of "
                f"{len(records)} within {_SECOND_WINDOW_BUDGET_S:.0f}s. This is the beat that "
                "separates 'the read was withheld by the selector' from 'this target delivers no "
                f"read data events at all' (the WriteOnly phase saw {withheld_count} records)."
            )
    reread = found[0]
    assert reread.get("readOnly") is True, (
        "GetObject reads, so the delivered record's readOnly must be True: actual "
        f"{reread.get('readOnly')!r}"
    )
    assert reread.get("eventCategory") == "Data", (
        f"eventCategory: expected 'Data', actual {reread.get('eventCategory')!r}"
    )
    # And the ORIGINAL withheld read must still be absent -- widening the selector must not
    # retroactively deliver events from before the change.
    late = [x for k in subject_keys for x in _for_key(records, "GetObject", k)]
    assert late == [], (
        "widening the selector must not retroactively deliver the reads that happened while it was "
        f"WriteOnly: expected 0 GetObject records naming any of {subject_keys}, actual {len(late)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
