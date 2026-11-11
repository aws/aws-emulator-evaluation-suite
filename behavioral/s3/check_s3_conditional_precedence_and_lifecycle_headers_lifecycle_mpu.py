"""s3-conditional-precedence-and-lifecycle-headers-lifecycle-mpu."""

from __future__ import annotations

import datetime
import email.utils

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-conditional-precedence-and-lifecycle-headers-lifecycle-mpu"
GROUP = 'lifecycle_rules'
SERVICES = ['s3']

_DAYS = 3                       # deliberately not 1, so a target hardcoding a 1-day window fails
_RULE_ID = "sim2real-s3cond-abort-mpu-3d"
_PREFIX = "staging/"


def _delete_bucket(client, bucket):
    """Abort open uploads, empty a bucket (objects + versions + markers), delete it; best-effort."""
    try:
        for page in client.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                client.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named bucket, register abort+empty+delete teardown, return its name."""
    name = ctx.unique_name("sim2real-s3cond-lcmpu-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _abort(s3, bucket, key, upload_id):
    """Best-effort abort of one multipart upload (teardown only)."""
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise


def _headers(resp):
    return {k.lower(): v for k, v in resp["ResponseMetadata"]["HTTPHeaders"].items()}


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """An AbortIncompleteMultipartUpload rule stamps x-amz-abort-date and x-amz-abort-rule-id on
    each matching upload, on CreateMultipartUpload and again on ListParts, and on no other upload.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket,
        LifecycleConfiguration={"Rules": [{
            "ID": _RULE_ID,
            "Filter": {"Prefix": _PREFIX},
            "Status": "Enabled",
            "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": _DAYS},
        }]},
    )
    (rule,) = [r for r in s3.get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"]
               if r["ID"] == _RULE_ID]
    assert rule["AbortIncompleteMultipartUpload"] == {"DaysAfterInitiation": _DAYS}, (
        f"the rule did not round-trip, got {rule!r}"
    )

    # Bracket the create with local timestamps to bound the server-computed abort date.
    key = _PREFIX + "matching-upload.bin"
    t0 = datetime.datetime.now(datetime.timezone.utc)
    created = s3.create_multipart_upload(Bucket=bucket, Key=key)
    t1 = datetime.datetime.now(datetime.timezone.utc)
    upload_id = created["UploadId"]
    ctx.on_cleanup(lambda: _abort(s3, bucket, key, upload_id))
    hdrs = _headers(created)

    assert hdrs.get("x-amz-abort-rule-id") == _RULE_ID, (
        f"CreateMultipartUpload under {_PREFIX!r} must carry x-amz-abort-rule-id={_RULE_ID!r}, "
        f"got {hdrs.get('x-amz-abort-rule-id')!r}"
    )
    raw_date = hdrs.get("x-amz-abort-date")
    assert raw_date is not None, (
        f"CreateMultipartUpload under {_PREFIX!r} must carry x-amz-abort-date; headers were "
        f"{sorted(hdrs)!r}"
    )
    abort_date = email.utils.parsedate_to_datetime(raw_date)

    # The server's own Date header bounds the create on S3's clock; the local t0/t1 bound it on
    # ours. Take the wider of the two so ordinary clock skew cannot fail a faithful target.
    # S3 adds DaysAfterInitiation to the creation time and rounds up to the next midnight UTC.
    server_date = email.utils.parsedate_to_datetime(hdrs["date"])
    earliest = min(t0, server_date) + datetime.timedelta(days=_DAYS)
    latest = max(t1, server_date + datetime.timedelta(seconds=1)) + datetime.timedelta(days=_DAYS + 1)
    assert earliest <= abort_date <= latest, (
        f"x-amz-abort-date {abort_date!r} must fall {_DAYS}-{_DAYS + 1} days after the upload was "
        f"created (local {t0!r}..{t1!r}, server {server_date!r})"
    )
    assert (abort_date.hour, abort_date.minute, abort_date.second) == (0, 0, 0), (
        f"x-amz-abort-date must be rounded to midnight UTC, got {raw_date!r}"
    )
    assert created.get("AbortDate") == abort_date and created.get("AbortRuleId") == _RULE_ID, (
        f"the SDK-parsed AbortDate/AbortRuleId {created.get('AbortDate')!r}/"
        f"{created.get('AbortRuleId')!r} disagree with the raw headers {raw_date!r}/{_RULE_ID!r}"
    )

    s3.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=b"p" * 1024)
    listed = s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id)
    lhdrs = _headers(listed)
    assert lhdrs.get("x-amz-abort-rule-id") == _RULE_ID, (
        f"ListParts must carry x-amz-abort-rule-id={_RULE_ID!r}, got {lhdrs.get('x-amz-abort-rule-id')!r}"
    )
    assert lhdrs.get("x-amz-abort-date") is not None, (
        f"ListParts must carry x-amz-abort-date; headers were {sorted(lhdrs)!r}"
    )
    listed_date = email.utils.parsedate_to_datetime(lhdrs["x-amz-abort-date"])
    assert listed_date == abort_date, (
        f"ListParts x-amz-abort-date {listed_date!r} differs from CreateMultipartUpload's "
        f"{abort_date!r}; the date must be fixed at initiation, not recomputed per read"
    )
    assert [p["PartNumber"] for p in listed.get("Parts", [])] == [1], (
        f"ListParts must show the one uploaded part, got {listed.get('Parts')!r}"
    )

    miss_key = "outside/control-upload.bin"
    miss = s3.create_multipart_upload(Bucket=bucket, Key=miss_key)
    miss_id = miss["UploadId"]
    ctx.on_cleanup(lambda: _abort(s3, bucket, miss_key, miss_id))
    mhdrs = _headers(miss)
    stray = {h: mhdrs[h] for h in ("x-amz-abort-date", "x-amz-abort-rule-id") if h in mhdrs}
    assert not stray, (
        f"an upload at {miss_key!r} does not match prefix {_PREFIX!r} yet CreateMultipartUpload "
        f"returned {stray!r}"
    )
    mlist = _headers(s3.list_parts(Bucket=bucket, Key=miss_key, UploadId=miss_id))
    stray = {h: mlist[h] for h in ("x-amz-abort-date", "x-amz-abort-rule-id") if h in mlist}
    assert not stray, f"ListParts on the prefix-miss upload returned {stray!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
