"""an-aborted-multipart-upload-emits-no-object-created-notification."""

from __future__ import annotations

import json
import time
import urllib.parse
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "an-aborted-multipart-upload-emits-no-object-created-notification"
GROUP = "event-propagation"
SERVICES = ["s3", "sqs"]

_PART = b"m" * 1024
#: Worst-case wall clock of this check's sequential polls, in seconds.
_WORST_CASE_BUDGET_S = 900


def _poll_until(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    """A bounded retry that RAISES on its deadline; never returns its last value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _client_error(fn):
    """The (code, message) of the ClientError raised by fn(). RAISES if fn() unexpectedly SUCCEEDS."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be rejected but it succeeded")


def _create_bucket(ctx, check_tag):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-nd-abortmpu-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":  # region-pinned API quirk, not a hardcoded region
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={
            "TagSet": [
                {"Key": "sim2real:managed", "Value": "true"},
                {"Key": "sim2real-check", "Value": check_tag},
            ]
        },
    )
    return name


def _delete_bucket(ctx, name):
    """An INCOMPLETE multipart upload blocks DeleteBucket and does not appear in ListObjectsV2, so
    the teardown must abort strays explicitly. Scoped to this bucket, which this check created."""
    s3 = ctx.client("s3")
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=name):
        for upload in page.get("Uploads", []):
            s3.abort_multipart_upload(
                Bucket=name, Key=upload["Key"], UploadId=upload["UploadId"]
            )
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
        stale = [
            {"Key": o["Key"], "VersionId": o["VersionId"]}
            for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
        ]
        if stale:
            s3.delete_objects(Bucket=name, Delete={"Objects": stale})
    s3.delete_bucket(Bucket=name)


def _make_queue(ctx, name, bucket, account, check_tag):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=name, tags={"sim2real-check": check_tag})["QueueUrl"]
    ctx.on_cleanup(lambda u=url: ctx.client("sqs").delete_queue(QueueUrl=u))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    sqs.set_queue_attributes(
        QueueUrl=url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowS3",
                            "Effect": "Allow",
                            "Principal": {"Service": "s3.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": arn,
                            "Condition": {
                                "StringEquals": {"aws:SourceAccount": account},
                                "ArnLike": {"aws:SourceArn": f"arn:*:s3:::{bucket}"},
                            },
                        }
                    ],
                }
            )
        },
    )
    return url, arn


def _drain_records(ctx, url, *, seconds):
    """`.get("Messages", [])` / `.get("Records", [])` feed a loop whose result is asserted by exact
    membership — the sanctioned polarity (S3's own s3:TestEvent message carries no Records)."""
    sqs = ctx.client("sqs")
    out = []
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            body = json.loads(msg["Body"])
            for record in body.get("Records", []):
                out.append(
                    {
                        "eventName": record["eventName"],
                        "key": urllib.parse.unquote_plus(record["s3"]["object"]["key"]),
                        "size": record["s3"]["object"].get("size"),
                    }
                )
            sqs.delete_message(QueueUrl=url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _queue_depth(ctx, url):
    attrs = ctx.client("sqs").get_queue_attributes(
        QueueUrl=url,
        AttributeNames=[
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "ApproximateNumberOfMessagesDelayed",
        ],
    )["Attributes"]
    return sum(int(v) for v in attrs.values())


def _one_part_upload(ctx, bucket, key):
    """Create a multipart upload and upload exactly one part. Returns (upload_id, etag)."""
    s3 = ctx.client("s3")
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
    etag = s3.upload_part(
        Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1, Body=_PART
    )["ETag"]
    parts = s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id).get("Parts", [])
    assert [p["PartNumber"] for p in parts] == [1], (
        f"ListParts for upload {upload_id} on {key!r} reports {parts!r}, expected exactly part 1 — "
        f"the bytes must be shown to have reached S3 before an absence of notification means anything"
    )
    return upload_id, etag


# ===== the check =====
@tags(
    "axis:negative-delivery",
    "cap:c2",
    "concern:data-plane",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """An aborted multipart upload emits no ObjectCreated notification even though its part was
    uploaded, while an identical completed upload emits exactly one CompleteMultipartUpload record.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/notification-how-to-event-types-and-destinations.html
    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_AbortMultipartUpload.html
    """
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    check_tag = CHECK
    suffix = uuid.uuid4().hex[:10]

    bucket = _create_bucket(ctx, check_tag)
    queue_url, queue_arn = _make_queue(
        ctx, f"sim2real-nd-abortmpu-{suffix}", bucket, account, check_tag
    )
    # As wide a subscription as S3 offers: every creation event, no prefix, no suffix.
    s3.put_bucket_notification_configuration(
        Bucket=bucket,
        NotificationConfiguration={
            "QueueConfigurations": [
                {"Id": "all-creates", "QueueArn": queue_arn, "Events": ["s3:ObjectCreated:*"]}
            ]
        },
    )
    stored = s3.get_bucket_notification_configuration(Bucket=bucket)["QueueConfigurations"]
    assert [c["Events"] for c in stored] == [["s3:ObjectCreated:*"]], (
        f"the stored notification configuration is {stored!r}, expected one unfiltered "
        f"s3:ObjectCreated:* subscription — anything narrower gives the absence a second explanation"
    )
    _drain_records(ctx, queue_url, seconds=8)  # discard S3's s3:TestEvent probe message

    # A single part is also the last part, so the 5 MiB minimum part size does not apply.
    done_key = f"mpu-completed-{suffix}.bin"
    done_id, done_etag = _one_part_upload(ctx, bucket, done_key)
    t0 = time.monotonic()
    s3.complete_multipart_upload(
        Bucket=bucket,
        Key=done_key,
        UploadId=done_id,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": done_etag}]},
    )
    records = _poll_until(
        lambda: _drain_records(ctx, queue_url, seconds=5),
        lambda recs: any(r["key"] == done_key for r in recs),
        timeout_s=180,
        interval_s=0,
        description=(
            f"the COMPLETED multipart upload of {done_key!r} produced a notification on {queue_url} — "
            f"the positive control that makes the absence below evidence"
        ),
    )
    latency = max(time.monotonic() - t0, 1.0)
    completed = [r for r in records if r["key"] == done_key]
    assert len(completed) == 1, (
        f"the completed upload produced {len(completed)} notification record(s) for {done_key!r}, "
        f"expected exactly 1: {completed!r} — one per CreateMultipartUpload/UploadPart/Complete would "
        f"be three, which is H2's failure mode"
    )
    assert completed[0]["eventName"] == "ObjectCreated:CompleteMultipartUpload", (
        f"the notification for {done_key!r} carries eventName={completed[0]['eventName']!r}, expected "
        f"'ObjectCreated:CompleteMultipartUpload' — a target that reports every creation as "
        f"'ObjectCreated:Put' is exactly what this literal detects"
    )
    assert completed[0]["size"] == len(_PART), (
        f"the notification reports size={completed[0]['size']!r}, expected {len(_PART)} — the assembled "
        f"object's byte count, not the request's"
    )

    abort_key = f"mpu-aborted-{suffix}.bin"
    abort_id, _ = _one_part_upload(ctx, bucket, abort_key)
    mid = _drain_records(ctx, queue_url, seconds=max(latency, 10.0))
    assert mid == [], (
        f"the queue received {len(mid)} record(s) between CreateMultipartUpload and UploadPart for "
        f"{abort_key!r}: {mid!r} — neither hop creates an object, so neither may notify (H2)"
    )
    s3.abort_multipart_upload(Bucket=bucket, Key=abort_key, UploadId=abort_id)

    parts_code, parts_message = _client_error(
        lambda: ctx.client("s3").list_parts(Bucket=bucket, Key=abort_key, UploadId=abort_id)
    )
    assert parts_code == "NoSuchUpload", (
        f"ListParts on the aborted upload {abort_id} answered {parts_code!r}, expected 'NoSuchUpload' "
        f"— an upload that still exists was not aborted, and the absence below would be a lost "
        f"notification rather than a withheld one"
    )
    assert parts_message == (
        "The specified upload does not exist. The upload ID may be invalid, or the upload may have "
        "been aborted or completed."
    ), f"ListParts on the aborted upload {abort_id} answered message {parts_message!r}"
    # HEAD responses carry no body, so the client sees the bare status and its reason phrase.
    head_code, head_message = _client_error(
        lambda: ctx.client("s3").head_object(Bucket=bucket, Key=abort_key)
    )
    assert (head_code, head_message) == ("404", "Not Found"), (
        f"head_object on {abort_key!r} answered {(head_code, head_message)!r}, expected "
        f"('404', 'Not Found') — the aborted upload must have assembled no object"
    )
    live_uploads = [
        u["UploadId"]
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket)
        for u in page.get("Uploads", [])
    ]
    assert abort_id not in live_uploads, (
        f"ListMultipartUploads still lists the aborted upload {abort_id}: {live_uploads!r}"
    )

    # Hold for 3x the measured completion latency before concluding nothing arrives.
    hold = max(3 * latency, 15.0)
    leaked = _drain_records(ctx, queue_url, seconds=hold)
    assert leaked == [], (
        f"the queue received {len(leaked)} notification record(s) during a {hold:.0f}s hold (3x the "
        f"{latency:.0f}s measured completion latency) for an upload that was ABORTED and assembled no "
        f"object: {leaked!r}"
    )
    assert _queue_depth(ctx, queue_url) == 0, (
        f"the queue reports depth {_queue_depth(ctx, queue_url)} behind an empty receive — the second "
        f"independent observable disagrees with the first"
    )

    # An abort cannot be undone, so a third completed upload shows notifications still work.
    encore_key = f"mpu-completed-again-{suffix}.bin"
    encore_id, encore_etag = _one_part_upload(ctx, bucket, encore_key)
    s3.complete_multipart_upload(
        Bucket=bucket,
        Key=encore_key,
        UploadId=encore_id,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": encore_etag}]},
    )
    encore = _poll_until(
        lambda: _drain_records(ctx, queue_url, seconds=5),
        lambda recs: any(r["key"] == encore_key for r in recs),
        timeout_s=180,
        interval_s=0,
        description=(
            f"a third, completed upload of {encore_key!r} still notifies AFTER the abort — the "
            f"emptiness above is the abort's doing, not a dead delivery path"
        ),
    )
    keys = sorted(r["key"] for r in encore)
    assert keys == [encore_key], (
        f"the queue carried {keys!r} on the final leg, expected exactly [{encore_key!r}] — the "
        f"aborted upload's key {abort_key!r} must never appear"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
