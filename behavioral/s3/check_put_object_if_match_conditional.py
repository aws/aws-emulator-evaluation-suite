"""put-object-if-match-conditional."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "put-object-if-match-conditional"
GROUP = 'conditional'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; only an already-gone
    bucket is tolerated, every other teardown error raises."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    # us-east-1 is S3's one region that refuses an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _err_code(fn):
    """Call fn(); return the ClientError response it raises. An unexpected SUCCESS raises, because a
    target ACCEPTING a stale If-Match is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(
        f"expected a stale If-Match PutObject to be rejected, but it SUCCEEDED and returned {result!r}"
    )


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject with If-Match succeeds only on the object's current ETag: the previous version's
    real ETag is refused with 412 PreconditionFailed and leaves the object unchanged, because
    accepting a stale If-Match silently loses data."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "if-match-obj.txt"

    v1_etag = s3.put_object(Bucket=bucket, Key=key, Body=b"v1-payload")["ETag"]
    v2_etag = s3.put_object(Bucket=bucket, Key=key, Body=b"v2-payload")["ETag"]
    assert v2_etag != v1_etag, f"expected v2 to carry a new ETag, both are {v1_etag!r}"

    # v1's real ETag is stale once v2 lands: the write is refused and the object is untouched.
    stale = _err_code(
        lambda: s3.put_object(Bucket=bucket, Key=key, Body=b"should-not-land", IfMatch=v1_etag)
    )
    stale_err = (stale.get("Error", {}).get("Code"), stale.get("Error", {}).get("Message"))
    stale_status = stale.get("ResponseMetadata", {}).get("HTTPStatusCode")
    expected = ("PreconditionFailed", "At least one of the pre-conditions you specified did not hold")
    assert stale_err == expected, f"expected {expected} for a stale If-Match, got {stale_err!r}"
    assert stale_status == 412, f"expected HTTP 412 for a stale If-Match, got {stale_status!r}"
    unchanged = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert unchanged == b"v2-payload", f"expected the stale If-Match PutObject to have NOT landed, body is {unchanged!r}"
    head_etag = s3.head_object(Bucket=bucket, Key=key)["ETag"]
    assert head_etag == v2_etag, f"HeadObject ETag {head_etag!r} != the pre-refusal ETag {v2_etag!r}"

    # The current ETag is accepted and actually updates the object.
    updated = s3.put_object(Bucket=bucket, Key=key, Body=b"updated-payload", IfMatch=v2_etag)
    assert updated["ETag"] != v2_etag, "expected a new ETag after the conditional update landed"

    final_body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert final_body == b"updated-payload", "expected the correctly-conditioned PutObject to land"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
