"""deep-s3-storage-class-versioned-expiration-rule-targets-current-version."""
from __future__ import annotations

import time
from email.utils import parsedate_to_datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-s3-storage-class-versioned-expiration-rule-targets-current-version"
GROUP = "storage-class"
SERVICES = ["s3"]


@tags("cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """On a versioned bucket the stored Expiration rule stamps only the current in-prefix version
    with x-amz-expiration naming the rule, and the versionless delete that expiry performs adds a
    delete marker while both data versions keep their exact bytes.
    """
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-dsc-ve-")
    key = "logs/app.log"
    outside = "other/app.log"
    rule_id = "expire-current-and-noncurrent"

    s3.create_bucket(**_bucket_kwargs(ctx, bucket))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    v1 = s3.put_object(Bucket=bucket, Key=key, Body=b"version-one")["VersionId"]
    v2 = s3.put_object(Bucket=bucket, Key=key, Body=b"version-two")["VersionId"]
    assert v1 and v2 and v1 != v2, f"versioned PUTs minted version ids {v1!r} and {v2!r}"
    s3.put_object(Bucket=bucket, Key=outside, Body=b"not-in-scope")

    rules = [{
        "ID": rule_id,
        "Status": "Enabled",
        "Filter": {"Prefix": "logs/"},
        "Expiration": {"Days": 3},
        "NoncurrentVersionExpiration": {"NoncurrentDays": 1, "NewerNoncurrentVersions": 1},
    }]
    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": rules})
    stored = _poll(ctx, lambda: _lifecycle_rules(s3, bucket), lambda got: isinstance(got, list))
    assert isinstance(stored, list) and len(stored) == 1, f"lifecycle read back as {stored!r}"
    assert stored[0].get("Expiration") == {"Days": 3}, f"stored Expiration {stored[0].get('Expiration')!r}"
    assert stored[0].get("NoncurrentVersionExpiration") == {"NoncurrentDays": 1, "NewerNoncurrentVersions": 1}, (
        f"stored NoncurrentVersionExpiration {stored[0].get('NoncurrentVersionExpiration')!r}"
    )

    versions = _versions(s3, bucket, "logs/")
    assert versions["markers"] == [], f"unexpected delete markers before expiry: {versions['markers']!r}"
    assert versions["versions"] == {v1: False, v2: True}, (
        f"version structure under logs/ was {versions['versions']!r}; expected v1 noncurrent, v2 current"
    )

    # The current version inside the prefix is stamped with this rule's expiration.
    expiration = _poll(ctx, lambda: s3.head_object(Bucket=bucket, Key=key).get("Expiration"), bool)
    assert expiration and f'rule-id="{rule_id}"' in expiration, (
        f"current version x-amz-expiration was {expiration!r}, expected it to name rule-id {rule_id!r}"
    )
    date_part = expiration.split('expiry-date="', 1)[1].split('"', 1)[0]
    head = s3.head_object(Bucket=bucket, Key=key)
    assert parsedate_to_datetime(date_part) > head["LastModified"], (
        f"expiry-date {date_part!r} is not after the object's LastModified {head['LastModified']!r}"
    )
    other = s3.head_object(Bucket=bucket, Key=outside)
    assert "Expiration" not in other, f"object outside the rule's prefix was stamped {other.get('Expiration')!r}"

    # What the Expiration action does to a versioned object: a versionless delete.
    deleted = s3.delete_object(Bucket=bucket, Key=key)
    assert deleted.get("DeleteMarker") is True, f"versionless delete did not report a delete marker: {deleted!r}"
    marker_id = deleted.get("VersionId")

    after = _versions(s3, bucket, "logs/")
    assert after["markers"] == [(marker_id, True)], f"delete markers after expiry act: {after['markers']!r}"
    assert after["versions"] == {v1: False, v2: False}, (
        f"data versions after expiry act: {after['versions']!r}; both must survive as noncurrent"
    )
    for vid, body in ((v1, b"version-one"), (v2, b"version-two")):
        data = s3.get_object(Bucket=bucket, Key=key, VersionId=vid)["Body"].read()
        assert data == body, f"version {vid!r} returned {data!r} after the delete marker, expected {body!r}"
    hidden = _error_code(lambda: s3.head_object(Bucket=bucket, Key=key))
    assert hidden == "404", f"versionless HeadObject behind the delete marker returned {hidden!r}, expected 404"


def _lifecycle_rules(s3, bucket: str):
    """The bucket's lifecycle Rules, or the error code GetBucketLifecycleConfiguration returns."""
    try:
        return s3.get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"]
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")


def _poll(ctx, fn, done, timeout_s: float = 60.0):
    """Call fn() every 2 s until done(result) or a 60 s deadline capped by ctx.time_left()."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        result = fn()
        if done(result) or time.monotonic() >= deadline:
            return result
        time.sleep(2)


def _versions(s3, bucket: str, prefix: str) -> dict:
    versions, markers = {}, []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=prefix):
        for v in page.get("Versions", []):
            versions[v["VersionId"]] = v["IsLatest"]
        for m in page.get("DeleteMarkers", []):
            markers.append((m["VersionId"], m["IsLatest"]))
    return {"versions": versions, "markers": markers}


def _bucket_kwargs(ctx, bucket: str) -> dict:
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    return kwargs


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
        for upload in page.get("Uploads", []):
            s3.abort_multipart_upload(Bucket=bucket, Key=upload["Key"], UploadId=upload["UploadId"])
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        for v in page.get("Versions", []) + page.get("DeleteMarkers", []):
            s3.delete_object(Bucket=bucket, Key=v["Key"], VersionId=v["VersionId"])
    s3.delete_bucket(Bucket=bucket)


def _error_code(fn):
    """Call fn(); return its botocore Error code. An unexpected SUCCESS raises, so an
    over-permissive target is never reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
