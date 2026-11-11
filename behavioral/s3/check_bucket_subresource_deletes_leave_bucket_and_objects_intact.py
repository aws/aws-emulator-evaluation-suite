"""bucket-subresource-deletes-leave-bucket-and-objects-intact."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-subresource-deletes-leave-bucket-and-objects-intact"
GROUP = "subresources"
SERVICES = ["s3"]

_KEY = "subresource-survivor.txt"
_BODY = b"subresource deletes must not touch me"
_METRICS_ID = "sim2real-metrics"
_NO_CONFIG = ("NoSuchConfiguration", "The specified configuration does not exist.")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _err(fn):
    """(Code, Message) of the ClientError ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _refused_eventually(fn, what: str, *, budget_s: float = 60.0):
    """(Code, Message) once ``fn`` is refused; a config delete may reach its GET a little late."""
    deadline = time.monotonic() + budget_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} still answered {budget_s}s after its delete: {result!r}")
        time.sleep(2)


def _empty_and_delete(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    s3.delete_bucket(Bucket=bucket)


def _assert_bucket_and_object(s3, bucket: str, etag: str, after: str) -> None:
    head = s3.head_bucket(Bucket=bucket)
    status = head["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"HeadBucket answered {status} after {after}; the bucket must survive"
    got = s3.get_object(Bucket=bucket, Key=_KEY)
    body = got["Body"].read()
    assert body == _BODY and got["ETag"] == etag, (
        f"after {after} the object reads {body!r} with ETag {got['ETag']!r}; expected the "
        f"original {_BODY!r} with ETag {etag!r}"
    )


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """Deleting a bucket's CORS, website, metrics, tagging, replication or policy subresource answers
    204 and removes only that subresource: each GET is refused with its exact NoSuch* error, a repeated
    CORS delete answers 204, a repeated metrics delete is NoSuchConfiguration, and the object survives."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-subres-")
    params: dict = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 must not be named as a LocationConstraint; every other region must be.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(_teardown(lambda: _empty_and_delete(s3, bucket), "NoSuchBucket"))

    etag = s3.put_object(Bucket=bucket, Key=_KEY, Body=_BODY)["ETag"]
    s3.put_bucket_cors(Bucket=bucket, CORSConfiguration={
        "CORSRules": [{"AllowedMethods": ["GET"], "AllowedOrigins": ["https://example.com"]}]})
    s3.put_bucket_website(Bucket=bucket, WebsiteConfiguration={
        "IndexDocument": {"Suffix": "index.html"}})
    s3.put_bucket_metrics_configuration(Bucket=bucket, Id=_METRICS_ID,
                                        MetricsConfiguration={"Id": _METRICS_ID})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "bucket-subresource-deletes"}]})

    # Positive control: every configured subresource is readable before any delete.
    cors = s3.get_bucket_cors(Bucket=bucket)["CORSRules"]
    assert [r["AllowedOrigins"] for r in cors] == [["https://example.com"]], cors
    website = s3.get_bucket_website(Bucket=bucket)
    assert website["IndexDocument"] == {"Suffix": "index.html"}, website
    metrics = s3.get_bucket_metrics_configuration(Bucket=bucket, Id=_METRICS_ID)
    assert metrics["MetricsConfiguration"]["Id"] == _METRICS_ID, metrics
    tag_set = s3.get_bucket_tagging(Bucket=bucket)["TagSet"]
    assert tag_set == [{"Key": "sim2real", "Value": "bucket-subresource-deletes"}], tag_set
    _assert_bucket_and_object(s3, bucket, etag, "configuring the subresources")

    deletes = [
        ("DeleteBucketCors", lambda: s3.delete_bucket_cors(Bucket=bucket)),
        ("DeleteBucketWebsite", lambda: s3.delete_bucket_website(Bucket=bucket)),
        ("DeleteBucketMetricsConfiguration",
         lambda: s3.delete_bucket_metrics_configuration(Bucket=bucket, Id=_METRICS_ID)),
        ("DeleteBucketTagging", lambda: s3.delete_bucket_tagging(Bucket=bucket)),
        ("DeleteBucketReplication on a bucket with none",
         lambda: s3.delete_bucket_replication(Bucket=bucket)),
        ("DeleteBucketPolicy on a bucket with none",
         lambda: s3.delete_bucket_policy(Bucket=bucket)),
    ]
    for label, delete in deletes:
        status = delete()["ResponseMetadata"]["HTTPStatusCode"]
        assert status == 204, f"{label} answered {status}, expected 204"
        _assert_bucket_and_object(s3, bucket, etag, label)

    gone = [
        ("GetBucketCors", lambda: s3.get_bucket_cors(Bucket=bucket),
         ("NoSuchCORSConfiguration", "The CORS configuration does not exist")),
        ("GetBucketWebsite", lambda: s3.get_bucket_website(Bucket=bucket),
         ("NoSuchWebsiteConfiguration",
          "The specified bucket does not have a website configuration")),
        ("GetBucketMetricsConfiguration",
         lambda: s3.get_bucket_metrics_configuration(Bucket=bucket, Id=_METRICS_ID), _NO_CONFIG),
        ("GetBucketTagging", lambda: s3.get_bucket_tagging(Bucket=bucket),
         ("NoSuchTagSet", "The TagSet does not exist")),
        ("GetBucketReplication", lambda: s3.get_bucket_replication(Bucket=bucket),
         ("ReplicationConfigurationNotFoundError", "The replication configuration was not found")),
        ("GetBucketPolicy", lambda: s3.get_bucket_policy(Bucket=bucket),
         ("NoSuchBucketPolicy", "The bucket policy does not exist")),
    ]
    for label, read, expected in gone:
        got = _refused_eventually(read, label)
        assert got == expected, f"{label} after its delete answered {got!r}, expected {expected!r}"

    # A repeated CORS delete is idempotent; a repeated metrics delete names the missing id.
    again = s3.delete_bucket_cors(Bucket=bucket)["ResponseMetadata"]["HTTPStatusCode"]
    assert again == 204, f"a second DeleteBucketCors answered {again}, expected 204"
    got = _err(lambda: s3.delete_bucket_metrics_configuration(Bucket=bucket, Id=_METRICS_ID))
    assert got == _NO_CONFIG, (
        f"a second DeleteBucketMetricsConfiguration answered {got!r}, expected {_NO_CONFIG!r}"
    )

    listed = [o["Key"] for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
              for o in page.get("Contents", [])]
    assert listed == [_KEY], f"after every subresource delete the bucket lists {listed!r}"
    _assert_bucket_and_object(s3, bucket, etag, "the repeated deletes")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
