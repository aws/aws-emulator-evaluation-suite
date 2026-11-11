"""s3-conditional-precedence-and-lifecycle-headers-get."""

from __future__ import annotations

import datetime

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-conditional-precedence-and-lifecycle-headers-get"
GROUP = 'conditional'
SERVICES = ['s3']

_BODY = b"s3cond-get-precedence-payload"
_PRECONDITION_FAILED = "At least one of the pre-conditions you specified did not hold"


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
    name = ctx.unique_name("sim2real-s3cond-get-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _outcome(fn):
    """Call fn(); return (http_status, error_code_or_None, body_or_error_message).

    A success returns its real 2xx status and the body bytes, so an unexpected success can never
    be mistaken for an error code.
    """
    try:
        resp = fn()
    except ClientError as exc:
        return (
            exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            exc.response.get("Error", {}).get("Code"),
            exc.response.get("Error", {}).get("Message"),
        )
    return resp["ResponseMetadata"]["HTTPStatusCode"], None, resp["Body"].read()


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """GetObject resolves paired conditional headers by S3's precedence rules: a holding If-Match
    overrides a failing If-Unmodified-Since, and If-None-Match decides over If-Modified-Since in both
    directions (304 or the body), each compared with the header sent alone."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "precedence/object.txt"

    put = s3.put_object(Bucket=bucket, Key=key, Body=_BODY)
    head = s3.head_object(Bucket=bucket, Key=key)
    etag = head["ETag"]
    last_modified = head["LastModified"]
    assert etag == put["ETag"], f"HEAD ETag {etag!r} differs from PutObject's {put['ETag']!r}"
    before = last_modified - datetime.timedelta(seconds=1)
    other_etag = '"00000000000000000000000000000000"'
    assert other_etag != etag, f"the non-matching ETag collided with the live one {etag!r}"

    def get(**kw):
        return _outcome(lambda: s3.get_object(Bucket=bucket, Key=key, **kw))

    # --- Controls: each header ALONE, so each pair below has a measured baseline.
    ius_alone = get(IfUnmodifiedSince=before)
    assert ius_alone == (412, "PreconditionFailed", _PRECONDITION_FAILED), (
        f"If-Unmodified-Since=LastModified-1s alone must fail 412 PreconditionFailed (the object "
        f"WAS modified after that instant); got {ius_alone!r}"
    )
    im_alone = get(IfMatch=etag)
    assert im_alone == (200, None, _BODY), f"If-Match=<live etag> alone must return the body, got {im_alone!r}"

    ims_before_alone = get(IfModifiedSince=before)
    assert ims_before_alone == (200, None, _BODY), (
        f"If-Modified-Since=LastModified-1s alone must return the body (the object WAS modified "
        f"after that instant); got {ims_before_alone!r}"
    )
    ims_at_alone = get(IfModifiedSince=last_modified)
    assert ims_at_alone == (304, "304", "Not Modified"), (
        f"If-Modified-Since=LastModified alone must be 304 Not Modified, got {ims_at_alone!r}"
    )
    inm_alone = get(IfNoneMatch=etag)
    assert inm_alone == (304, "304", "Not Modified"), (
        f"If-None-Match=<live etag> alone must be 304 Not Modified, got {inm_alone!r}"
    )

    # --- Pair 1: If-Match true overrides If-Unmodified-Since false -> 200 WITH the body.
    pair1 = get(IfMatch=etag, IfUnmodifiedSince=before)
    assert pair1 == (200, None, _BODY), (
        f"If-Match=<live etag> + If-Unmodified-Since=LastModified-1s must return 200 with the body "
        f"(If-Match satisfied means If-Unmodified-Since is ignored); got {pair1!r}"
    )

    # --- Pair 2: If-None-Match false beats If-Modified-Since true -> 304, not the body.
    pair2 = get(IfNoneMatch=etag, IfModifiedSince=before)
    assert pair2 == (304, "304", "Not Modified"), (
        f"If-None-Match=<live etag> + If-Modified-Since=LastModified-1s must be 304 with no body "
        f"(If-None-Match decides), even though If-Modified-Since alone returned the body; got {pair2!r}"
    )

    # --- Pair 3: If-None-Match true overrides If-Modified-Since false -> 200 with the body.
    pair3 = get(IfNoneMatch=other_etag, IfModifiedSince=last_modified)
    assert pair3 == (200, None, _BODY), (
        f"If-None-Match=<other etag> + If-Modified-Since=LastModified must return the body "
        f"(If-None-Match satisfied means If-Modified-Since is ignored), even though "
        f"If-Modified-Since alone was 304; got {pair3!r}"
    )

    # --- Pair 4 (the override is one-way): If-Match FALSE still fails even with a true
    # If-Unmodified-Since, so pair 1 is precedence and not "any true condition passes".
    future_ius = last_modified + datetime.timedelta(days=1)
    pair4 = get(IfMatch=other_etag, IfUnmodifiedSince=future_ius)
    assert pair4 == (412, "PreconditionFailed", _PRECONDITION_FAILED), (
        f"If-Match=<other etag> + If-Unmodified-Since=<future> must fail 412 PreconditionFailed; "
        f"got {pair4!r}"
    )

    # --- The object is untouched by all of the above.
    final = s3.head_object(Bucket=bucket, Key=key)
    assert (final["ETag"], final["LastModified"]) == (etag, last_modified), (
        f"conditional reads must not mutate the object; ETag/LastModified went from "
        f"{(etag, last_modified)!r} to {(final['ETag'], final['LastModified'])!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
