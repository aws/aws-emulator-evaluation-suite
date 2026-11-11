"""create-bucket-invalid-name-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-bucket-invalid-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["s3"]

_INVALID_NAME = "InvalidBucketName"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateBucket with a name over 63 characters is rejected with 400 InvalidBucketName, its exact
    message and the BucketName, and is not listed, while a valid name is created and listed."""
    s3 = ctx.client("s3")

    good_name = ctx.unique_name("sim2real-behav-s3fid-")
    assert len(good_name) <= 63
    good_params: dict = {"Bucket": good_name}
    if ctx.region != "us-east-1":
        good_params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**good_params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, good_name))
    s3.put_bucket_tagging(Bucket=good_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.head_bucket(
        Bucket=good_name
    )  # independent read: the control bucket really exists

    too_long = good_name + ("z" * 64)
    assert len(too_long) > 63
    # Only does anything if the create below unexpectedly lands.
    ctx.on_cleanup(lambda: _delete_bucket(s3, too_long))

    params: dict = {"Bucket": too_long}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}

    refusal = _error(lambda: s3.create_bucket(**params))
    err = refusal.get("Error", {})
    status = refusal.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert err.get("Code") == _INVALID_NAME, (
        f"expected {_INVALID_NAME!r} for a 64+ char bucket name, got {err.get('Code')!r}"
    )
    assert status == 400, f"expected HTTP 400 for {_INVALID_NAME}, got {status!r}"
    assert err.get("Message") == "The specified bucket is not valid.", (
        f"expected the exact {_INVALID_NAME} message, got {err!r}"
    )
    assert err.get("BucketName") == too_long, (
        f"expected Error.BucketName to be the supplied {len(too_long)}-char name, got {err.get('BucketName')!r}"
    )

    # Nothing was created: HeadBucket on the refused name is refused (a bodiless 4xx: the name
    # is invalid as well as absent), and ListBuckets omits it.
    head = _error(lambda: s3.head_bucket(Bucket=too_long))
    head_status = head.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert head_status in (400, 404), (
        f"expected HeadBucket on the refused name to answer 400 or 404, got {head_status!r}"
    )
    names = [b["Name"] for b in s3.list_buckets(Prefix=good_name).get("Buckets", [])]
    assert too_long not in names, "the refused bucket name is listed by ListBuckets"
    assert good_name in names, f"the control bucket is missing from ListBuckets: {names!r}"


def _error(fn):
    """Call fn(); return the ClientError response it raises. A call that SUCCEEDS fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_bucket(client, bucket):
    """Teardown: empty then delete. Only a bucket that never existed (NoSuchBucket, or
    InvalidBucketName for the over-long name) is tolerated; every other error raises."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("NoSuchBucket", "InvalidBucketName"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
