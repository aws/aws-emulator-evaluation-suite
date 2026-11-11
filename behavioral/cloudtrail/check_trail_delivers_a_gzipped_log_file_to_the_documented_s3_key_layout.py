"""trail-delivers-a-gzipped-log-file-to-the-documented-s3-key-layout."""

from __future__ import annotations

import datetime
import gzip
import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trail-delivers-a-gzipped-log-file-to-the-documented-s3-key-layout"
GROUP = "data-plane"
SERVICES = ["cloudtrail"]

# Carried in the failure detail when no log file is delivered, so the miss is graded as a
# data-plane FAIL rather than dropping out of the denominator.
DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"

# CloudTrail delivers log files in about 5 minutes on average and does not guarantee it.
_DELIVERY_BUDGET_S = 900.0
_DELIVERY_POLL_S = 2.0
# A trail that just started logging can miss its first calls, so a marker with a fresh token
# is made this often.
_MARKER_REPEAT_S = 60.0
# LookupEvents indexing lags only a few minutes; by the time an S3 log file has landed the index
# has caught up, so this secondary poll is short.
_INDEX_BUDGET_S = 180.0
_INDEX_POLL_S = 2.0
_PAGE_CEILING = 40

# The YYYYMMDDTHHmmZ stamp in a delivered log file's name.
_FILENAME_STAMP_RE = re.compile(r"_(\d{8}T\d{4})Z_")

# Every swallow is narrowed to ClientError so a real defect fails the check.


def _call(
    fn,
    retry_codes=(
        "ThrottlingException",
        "MaximumNumberOfTrailsExceededException",
        "ConflictException",
        "InsufficientS3BucketPolicyException",
    ),
    attempts=7,
):
    """Invoke fn(), retrying transient CloudTrail control-plane errors. Raises the last error."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in retry_codes and i < attempts - 1:
                last = exc
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise last


def _create_trail_bucket(s3, bucket, region, account_id):
    """Create-or-adopt an S3 bucket carrying the policy CloudTrail needs to deliver logs."""
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in (
            "BucketAlreadyOwnedByYou",
            "BucketAlreadyExists",
        ):
            raise
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": [
                    f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                    f"arn:aws:s3:::{bucket}/*/AWSLogs/{account_id}/*",
                ],
                "Condition": {
                    "StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}
                },
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _purge_bucket_once(s3, bucket):
    """Delete every current object and every non-current version. Returns objects removed."""
    removed = 0
    for paginator_name, list_key, id_key in (
        ("list_objects_v2", "Contents", None),
        ("list_object_versions", "Versions", "VersionId"),
        ("list_object_versions", "DeleteMarkers", "VersionId"),
    ):
        paginator = s3.get_paginator(paginator_name)
        try:
            for page in paginator.paginate(Bucket=bucket):
                entries = page.get(list_key, [])
                if not entries:
                    continue
                objects = []
                for entry in entries:
                    item = {"Key": entry["Key"]}
                    if id_key and entry.get(id_key):
                        item["VersionId"] = entry[id_key]
                    objects.append(item)
                s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
                removed += len(objects)
        except ClientError:
            continue
    return removed


def _drain_and_delete_bucket(s3, bucket, *, attempts=8, delay_s=15.0):
    """Empty and delete the log bucket, retrying: CloudTrail may still be writing, and a file that
    lands between purge and delete fails DeleteBucket with BucketNotEmpty. RAISES on deadline."""
    last = None
    for attempt in range(attempts):
        _purge_bucket_once(s3, bucket)
        try:
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NoSuchBucket":
                return
            last = exc
            if attempt < attempts - 1:
                time.sleep(delay_s)
    raise AssertionError(
        f"could not delete trail log bucket {bucket} after {attempts} attempts; a billable S3 "
        f"bucket and its CloudTrail log files have been LEAKED. Last error: {last}"
    )


def _delete_trail_idempotent(ct, name):
    """Idempotent teardown net: stop logging then delete, tolerating an already-deleted trail."""
    for fn in (lambda: ct.stop_logging(Name=name), lambda: ct.delete_trail(Name=name)):
        try:
            _call(fn)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "TrailNotFoundException":
                raise


def _error_code(fn):
    """The exact AWS error code and message, RAISING if the call unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError("call unexpectedly SUCCEEDED where an error was required")


def _lookup_all(ct, **kw):
    """Page LookupEvents to exhaustion (bounded). Never assert membership in one page."""
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


def _iter_log_objects(s3, bucket, prefixes):
    """Every object key under any of `prefixes`, bounded by the paginator."""
    keys = []
    paginator = s3.get_paginator("list_objects_v2")
    for prefix in prefixes:
        for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
            for entry in page.get("Contents", []):
                keys.append(entry["Key"])
    return keys


# timing:real-time — buffer: 300 s
@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c2",
      "timing:real-time")
def run(ctx) -> None:
    """A trail delivers THIS check's own API call to S3 as a gzipped {"Records": [...]} log file
    under the documented AWSLogs/<account>/CloudTrail/<region>/YYYY/MM/DD key layout, with the same
    eventID LookupEvents reports, and GetTrailStatus reports the delivery.

    Reference: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/get-and-view-cloudtrail-log-files.html
    """
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region

    bucket = ctx.unique_name("sim2real-behav-ctdeliv-")
    trail_name = ctx.unique_name("sim2real-behav-ctdeliv-")
    _create_trail_bucket(s3, bucket, region, account)
    ctx.on_cleanup(lambda: _drain_and_delete_bucket(s3, bucket))

    created = _call(
        lambda: ct.create_trail(
            Name=trail_name,
            S3BucketName=bucket,
            IsMultiRegionTrail=False,
            IncludeGlobalServiceEvents=False,
            TagsList=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: _delete_trail_idempotent(ct, trail_name))
    trail_arn = created["TrailARN"]
    assert trail_arn.endswith(f":trail/{trail_name}"), (
        f"CreateTrail returned TrailARN {trail_arn!r}, which does not name the trail this "
        f"check asked for ({trail_name!r})"
    )

    _call(lambda: ct.start_logging(Name=trail_name))
    logging_started_at = datetime.datetime.now(datetime.timezone.utc)

    status = _call(lambda: ct.get_trail_status(Name=trail_name))
    assert status["IsLogging"] is True, (
        f"GetTrailStatus reports IsLogging={status.get('IsLogging')!r} immediately after a "
        f"successful StartLogging on {trail_name!r}; expected True. Nothing below is "
        f"interpretable if the trail is not logging."
    )

    # The marker: a read-only management call whose arguments carry a run-unique token, made
    # AFTER StartLogging so it is inside the trail's coverage. It creates nothing and bills
    # nothing, and the token lands verbatim in the record's requestParameters.
    token = ctx.unique_name("sim2realctdelivmarker").lower()
    emitted_at = datetime.datetime.now(datetime.timezone.utc)
    t0 = time.monotonic()
    ct.describe_trails(trailNameList=[token])
    tokens = [token]
    next_marker = t0 + _MARKER_REPEAT_S

    # The delivery date is the UTC date CloudTrail wrote the file, which near midnight can
    # be the day after the call. Both prefixes are watched rather than guessing which.
    def _date_prefixes():
        now = datetime.datetime.now(datetime.timezone.utc)
        days = {
            now.date(),
            (now + datetime.timedelta(days=1)).date(),
            (now - datetime.timedelta(days=1)).date(),
        }
        base = f"AWSLogs/{account}/CloudTrail/{region}/"
        return [f"{base}{d.year:04d}/{d.month:02d}/{d.day:02d}/" for d in sorted(days)]

    found_key = None
    found_record = None
    seen_keys: set[str] = set()
    polls = 0
    while time.monotonic() - t0 < _DELIVERY_BUDGET_S:
        polls += 1
        for key in _iter_log_objects(s3, bucket, _date_prefixes()):
            if key in seen_keys:
                continue
            seen_keys.add(key)
            raw = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            assert raw[:2] == b"\x1f\x8b", (
                f"delivered object {key!r} does not start with the gzip magic bytes "
                f"1f 8b; first bytes were {raw[:8]!r}. CloudTrail publishes log files "
                f"in a gzip archive, so a consumer that gunzips unconditionally breaks here"
            )
            payload = json.loads(gzip.decompress(raw).decode("utf-8"))
            assert set(payload) == {"Records"}, (
                f"the inflated body of {key!r} has top-level keys {sorted(payload)!r}; "
                f"expected exactly ['Records']"
            )
            assert isinstance(payload["Records"], list), (
                f"{key!r}: Records is {type(payload['Records']).__name__}, not a list"
            )
            for record in payload["Records"]:
                dumped = json.dumps(record)
                matched = next((t for t in tokens if t in dumped), None)
                if matched is not None:
                    # Every later assertion follows the one call this record describes.
                    token = matched
                    found_key, found_record = key, record
                    break
            if found_record is not None:
                break
        if found_record is not None:
            break
        if time.monotonic() >= next_marker:
            tokens.append(ctx.unique_name("sim2realctdelivmarker").lower())
            ct.describe_trails(trailNameList=[tokens[-1]])
            next_marker = time.monotonic() + _MARKER_REPEAT_S
        time.sleep(_DELIVERY_POLL_S)
    waited = time.monotonic() - t0

    if found_record is None:
        # Diagnostic-only: the producer's own status may name the reason (e.g. a bucket
        # policy CloudTrail's write is being denied against) even though nothing landed.
        diag_status = _call(lambda: ct.get_trail_status(Name=trail_name))
        diag = {
            k: diag_status.get(k)
            for k in (
                "LatestDeliveryError",
                "LatestDeliveryAttemptTime",
                "LatestDeliveryTime",
            )
        }
    assert found_record is not None, (
        f"{DATAPLANE_MARKER}: the trail delivered no log file containing an API call this check "
        f"itself made. Trail {trail_name!r} was logging to bucket {bucket!r} from "
        f"{logging_started_at.isoformat()}; a DescribeTrails call carrying the unique token "
        f"{token!r} was first made at {emitted_at.isoformat()}; {polls} polls over {waited:.0f}s read "
        f"{len(seen_keys)} object(s) under AWSLogs/{account}/CloudTrail/{region}/ and none of "
        f"them mentioned it. GetTrailStatus reports {diag!r}. Real AWS documents delivery at an "
        f"average of about 5 minutes. A target that stores a trail's configuration but never "
        f"writes a log file is not delivering anything, which is the whole product."
    )

    # --- The KEY is the documented layout, derived from live values.
    assert found_key.startswith(f"AWSLogs/{account}/CloudTrail/{region}/"), (
        f"the delivered object key is {found_key!r}; the documented layout for management and "
        f"data events is AWSLogs/<account>/CloudTrail/<region>/YYYY/MM/DD/<file>, so with no "
        f"S3KeyPrefix set it must start AWSLogs/{account}/CloudTrail/{region}/"
    )
    date_part = found_key[len(f"AWSLogs/{account}/CloudTrail/{region}/") :].split("/")
    assert len(date_part) == 4, (
        f"the key tail after the region segment is {date_part!r}; expected exactly "
        f"[YYYY, MM, DD, filename] (4 segments) in {found_key!r}"
    )
    year, month, day, filename = date_part
    key_date = datetime.date(int(year), int(month), int(day))
    assert abs((key_date - emitted_at.date()).days) <= 1, (
        f"the key's date segments {year}/{month}/{day} denote {key_date}, which is more than "
        f"one day from the UTC date the call was made ({emitted_at.date()})"
    )
    assert filename.startswith(f"{account}_CloudTrail_{region}_"), (
        f"the delivered file name is {filename!r}; the documented format is "
        f"<AccountID>_CloudTrail_<Region>_<YYYYMMDDTHHmmZ>_<UniqueString>.json.gz, so it must "
        f"start {account}_CloudTrail_{region}_"
    )
    assert filename.endswith(".json.gz"), (
        f"the delivered file name is {filename!r}; it must end .json.gz"
    )
    stamp = _FILENAME_STAMP_RE.search(filename)
    assert stamp is not None, (
        f"the delivered file name {filename!r} carries no YYYYMMDDTHHmmZ timestamp segment "
        f"between the region and the disambiguating string"
    )
    stamped = datetime.datetime.strptime(stamp.group(1), "%Y%m%dT%H%M").replace(
        tzinfo=datetime.timezone.utc
    )
    # Two-sided: the stamp is the delivery window, so it is at or after the call, and not
    # unboundedly later. A target that stamps the file with the delivery instant of a template
    # or with epoch fails one side or the other.
    assert stamped >= emitted_at - datetime.timedelta(minutes=5), (
        f"the file name's timestamp {stamped.isoformat()} is more than 5 minutes BEFORE the "
        f"call it carries ({emitted_at.isoformat()}); the stamp names the delivery window"
    )
    assert stamped <= datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(
        minutes=5
    ), (
        f"the file name's timestamp {stamped.isoformat()} is in the future relative to now"
    )

    # --- The RECORD describes this call, not merely some call.
    assert found_record["eventName"] == "DescribeTrails", (
        f"the delivered record matching this run's token names operation "
        f"{found_record.get('eventName')!r}, expected DescribeTrails"
    )
    assert found_record["eventSource"] == "cloudtrail.amazonaws.com", (
        f"eventSource is {found_record.get('eventSource')!r}, expected cloudtrail.amazonaws.com"
    )
    assert found_record["requestParameters"] == {"trailNameList": [token]}, (
        f"the delivered record must reproduce the request verbatim; the call passed "
        f"trailNameList=[{token!r}] but the record carries "
        f"{found_record.get('requestParameters')!r}. A target that logs the operation but "
        f"discards its arguments fails here"
    )
    assert found_record["awsRegion"] == region, (
        f"awsRegion is {found_record.get('awsRegion')!r}, expected {region!r}"
    )
    assert found_record["recipientAccountId"] == account, (
        f"recipientAccountId is {found_record.get('recipientAccountId')!r}, expected {account!r}"
    )
    assert found_record["eventCategory"] == "Management", (
        f"eventCategory is {found_record.get('eventCategory')!r}, expected Management -- a "
        f"trail with default selectors logs management events"
    )
    assert found_record["readOnly"] is True, (
        f"readOnly is {found_record.get('readOnly')!r} for DescribeTrails, a read-only "
        f"operation; the member is a JSON boolean in the log file, not a string"
    )
    event_id = found_record["eventID"]
    assert event_id, f"the delivered record carries no eventID: {found_record!r}"

    # --- The SAME event, through a second and entirely separate delivery path, has the
    # same identity. An emulator that synthesises S3 log files and the LookupEvents index
    # independently disagrees here even when each looks individually plausible.
    index_t0 = time.monotonic()
    envelope = None
    index_polls = 0
    while time.monotonic() - index_t0 < _INDEX_BUDGET_S:
        index_polls += 1
        events = _lookup_all(
            ct,
            StartTime=emitted_at - datetime.timedelta(minutes=5),
            EndTime=datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(minutes=5),
            MaxResults=50,
            LookupAttributes=[
                {"AttributeKey": "EventName", "AttributeValue": "DescribeTrails"}
            ],
        )
        for ev in events:
            if token in ev.get("CloudTrailEvent", ""):
                envelope = ev
                break
        if envelope is not None:
            break
        time.sleep(_INDEX_POLL_S)
    assert envelope is not None, (
        f"{DATAPLANE_MARKER}: the call was delivered to S3 (key {found_key!r}, eventID "
        f"{event_id!r}) but LookupEvents never returned it after {index_polls} polls over "
        f"{time.monotonic() - index_t0:.0f}s. The two delivery paths disagree about whether "
        f"the call happened at all"
    )
    assert envelope["EventId"] == event_id, (
        f"the eventID in the delivered S3 log file ({event_id!r}) is not the EventId "
        f"LookupEvents reports for the same call ({envelope['EventId']!r}). One event is "
        f"assigned one id once; a target minting ids per delivery path cannot make them equal"
    )

    # --- The producer's own status reports the delivery it just made.
    final = _call(lambda: ct.get_trail_status(Name=trail_name))
    assert "LatestDeliveryError" not in final, (
        f"GetTrailStatus reports LatestDeliveryError={final.get('LatestDeliveryError')!r} on a "
        f"trail that demonstrably delivered {found_key!r}; the member is OMITTED until a "
        f"delivery has failed"
    )
    assert "LatestDeliveryTime" in final, (
        f"GetTrailStatus omits LatestDeliveryTime on a trail that demonstrably delivered "
        f"{found_key!r}; response keys were {sorted(final)!r}"
    )
    assert final["LatestDeliveryTime"] >= logging_started_at - datetime.timedelta(
        minutes=1
    ), (
        f"LatestDeliveryTime {final['LatestDeliveryTime']!r} predates StartLogging "
        f"({logging_started_at.isoformat()}), so it cannot describe this delivery"
    )
    # LatestDeliveryAttemptSucceeded is NOT the string "true": AWS answers the ISO-8601 UTC instant
    # of the last successful delivery attempt, a STRING dated no earlier than StartLogging.
    attempt = final.get("LatestDeliveryAttemptSucceeded")
    assert isinstance(attempt, str) and attempt, (
        f"LatestDeliveryAttemptSucceeded is {attempt!r}; the member is STRING-typed and must be "
        f"populated after a successful delivery"
    )
    try:
        attempt_at = datetime.datetime.strptime(attempt, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc
        )
    except ValueError as exc:
        raise AssertionError(
            f"LatestDeliveryAttemptSucceeded {attempt!r} is not the '%Y-%m-%dT%H:%M:%SZ' instant "
            f"real AWS reports for the last successful delivery attempt: {exc}"
        )
    assert attempt_at >= logging_started_at - datetime.timedelta(minutes=1), (
        f"LatestDeliveryAttemptSucceeded {attempt!r} predates StartLogging "
        f"({logging_started_at.isoformat()}), so it cannot describe this delivery"
    )

    # --- The delete is proved, not assumed. The trail is gone by an independent read, and
    # an operation that demonstrably worked above now fails with the specific not-found code.
    _call(lambda: ct.stop_logging(Name=trail_name))
    _call(lambda: ct.delete_trail(Name=trail_name))
    unknown = f"Unknown trail: {trail_arn} for the user: {account}"
    code, message = _error_code(lambda: ct.get_trail_status(Name=trail_name))
    assert code == "TrailNotFoundException", (
        f"GetTrailStatus on the deleted trail {trail_name!r} answered {code!r}, expected "
        f"TrailNotFoundException"
    )
    assert message == unknown, f"GetTrailStatus on the deleted trail answered {message!r}"
    code, message = _error_code(lambda: ct.start_logging(Name=trail_name))
    assert code == "TrailNotFoundException", (
        f"StartLogging -- which succeeded on this trail earlier in this run -- answered {code!r} "
        f"on the deleted name, expected TrailNotFoundException; a dead trail must be unusable, "
        f"not merely unreadable"
    )
    assert message == unknown, f"StartLogging on the deleted trail answered {message!r}"
    # The already-delivered log file survives the trail's deletion.
    surviving = s3.head_object(Bucket=bucket, Key=found_key)
    assert surviving["ContentLength"] > 0, (
        f"the delivered log file {found_key!r} is empty or gone after the trail was deleted; "
        f"deleting a trail must not retract log files already written to the customer's bucket"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
