"""s3-conditional-precedence-and-lifecycle-headers-copy."""

from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-conditional-precedence-and-lifecycle-headers-copy"
GROUP = 'conditional'
SERVICES = ['s3']

_BODY = b"s3cond-copy-precedence-source"


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; raises unless gone."""
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
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = ctx.unique_name("sim2real-s3cond-copy-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _exists(s3, bucket, key):
    """True if HEAD finds the key, False on a 404; any other error propagates."""
    try:
        s3.head_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        if exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404:
            return False
        raise
    return True


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """CopyObject resolves paired x-amz-copy-source-if-* headers by S3's precedence rules (a true IfMatch
    overrides a false IfUnmodifiedSince, IfNoneMatch decides over IfModifiedSince), and every failed
    precondition is 412 PreconditionFailed with no destination written."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    src = "source/object.txt"
    s3.put_object(Bucket=bucket, Key=src, Body=_BODY)
    head = s3.head_object(Bucket=bucket, Key=src)
    etag = head["ETag"]
    last_modified = head["LastModified"]
    before = last_modified - datetime.timedelta(seconds=1)
    other_etag = '"00000000000000000000000000000000"'
    assert other_etag != etag, f"the non-matching ETag collided with the live one {etag!r}"
    copy_source = {"Bucket": bucket, "Key": src}

    def copy(dest, **kw):
        """Return (status, error_code_or_None, error_message_or_None) and the effect: whether
        dest exists afterwards."""
        try:
            resp = s3.copy_object(Bucket=bucket, Key=dest, CopySource=copy_source, **kw)
            outcome = (resp["ResponseMetadata"]["HTTPStatusCode"], None, None)
        except ClientError as exc:
            outcome = (
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
                exc.response.get("Error", {}).get("Code"),
                exc.response.get("Error", {}).get("Message"),
            )
        return outcome, _exists(s3, bucket, dest)

    def accepted(label, dest, **kw):
        outcome, present = copy(dest, **kw)
        assert outcome == (200, None, None), (
            f"{label}: expected the copy to succeed (200), got {outcome!r}"
        )
        assert present, f"{label}: the copy returned 200 but {dest!r} does not exist"
        body = s3.get_object(Bucket=bucket, Key=dest)["Body"].read()
        assert body == _BODY, f"{label}: copied bytes differ from the source, got {body!r}"

    def rejected(label, dest, **kw):
        outcome, present = copy(dest, **kw)
        assert outcome == (
            412, "PreconditionFailed", "At least one of the pre-conditions you specified did not hold"
        ), (
            f"{label}: expected 412 PreconditionFailed, got {outcome!r}"
        )
        assert not present, f"{label}: the copy was refused yet {dest!r} was written"

    # --- Controls: each header alone.
    rejected("CopySourceIfUnmodifiedSince=LM-1s alone", "dest/ius-alone",
             CopySourceIfUnmodifiedSince=before)
    accepted("CopySourceIfMatch=<etag> alone", "dest/im-alone", CopySourceIfMatch=etag)
    accepted("CopySourceIfModifiedSince=LM-1s alone", "dest/ims-before-alone",
             CopySourceIfModifiedSince=before)
    rejected("CopySourceIfModifiedSince=LM alone (not 304 as on GET)", "dest/ims-at-alone",
             CopySourceIfModifiedSince=last_modified)
    rejected("CopySourceIfNoneMatch=<etag> alone (not 304 as on GET)", "dest/inm-alone",
             CopySourceIfNoneMatch=etag)

    # --- Pair 1: if-match true overrides if-unmodified-since false.
    accepted("CopySourceIfMatch=<etag> + CopySourceIfUnmodifiedSince=LM-1s", "dest/pair1",
             CopySourceIfMatch=etag, CopySourceIfUnmodifiedSince=before)
    # --- Pair 2: if-none-match false beats if-modified-since true.
    rejected("CopySourceIfNoneMatch=<etag> + CopySourceIfModifiedSince=LM-1s", "dest/pair2",
             CopySourceIfNoneMatch=etag, CopySourceIfModifiedSince=before)
    # --- Pair 3: if-none-match true overrides if-modified-since false.
    accepted("CopySourceIfNoneMatch=<other> + CopySourceIfModifiedSince=LM", "dest/pair3",
             CopySourceIfNoneMatch=other_etag, CopySourceIfModifiedSince=last_modified)
    # --- Pair 4: the override is one-way; a false if-match still rejects.
    rejected("CopySourceIfMatch=<other> + CopySourceIfUnmodifiedSince=<future>", "dest/pair4",
             CopySourceIfMatch=other_etag,
             CopySourceIfUnmodifiedSince=last_modified + datetime.timedelta(days=1))

    # --- The source is untouched, and exactly the accepted destinations exist.
    final = s3.head_object(Bucket=bucket, Key=src)
    assert (final["ETag"], final["LastModified"]) == (etag, last_modified), (
        f"conditional copies must not mutate the source; went from {(etag, last_modified)!r} "
        f"to {(final['ETag'], final['LastModified'])!r}"
    )
    keys = set()
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix="dest/"):
        keys.update(o["Key"] for o in page.get("Contents", []))
    expected = {"dest/im-alone", "dest/ims-before-alone", "dest/pair1", "dest/pair3"}
    assert keys == expected, f"destinations present {sorted(keys)!r}, expected {sorted(expected)!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
