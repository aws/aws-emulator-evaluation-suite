"""s3-refused-conditional-gets-create-no-version-and-leave-the-object-intact."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-refused-conditional-gets-create-no-version-and-leave-the-object-intact"
GROUP = 'conditional-rejection'
SERVICES = ['s3']

_BODY = b"conditional-read-payload-that-must-survive-two-refusals-byte-for-byte"
_STALE_ETAG = '"00000000000000000000000000000000"'


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; best-effort teardown."""
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


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn, what):
    """Call fn() and return the ClientError it raised; raise AssertionError if it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected {what} to be refused with a ClientError, but it succeeded")


def _versions_for_key(client, bucket, key):
    """Return every version id currently listed for one key (versions + delete markers)."""
    found = []
    for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket, Prefix=key):
        for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
            if o["Key"] == key:
                found.append(o["VersionId"])
    return found


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A refused conditional GET leaves a versioned object's version history unchanged.

    After a 304 (If-None-Match on the current ETag) and a 412 (stale If-Match), ListObjectVersions
    lists the same single version, and If-Match on the current ETag still serves the exact bytes.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    versioning = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    assert versioning == "Enabled", (
        f"the bucket must report versioning Enabled before a refused read can be graded for "
        f"minting no version, GetBucketVersioning reports {versioning!r}"
    )

    key = "conditional-read/payload.bin"
    put = s3.put_object(Bucket=bucket, Key=key, Body=_BODY)
    live_etag = put["ETag"]
    live_version = put.get("VersionId")
    assert live_version and live_version != "null", (
        f"a versioning-enabled bucket must return a real VersionId from PutObject, got "
        f"{live_version!r} -- the 'null' sentinel is what an unversioned bucket reports, and "
        f"against it the before/after version lists would match no matter what a read did"
    )

    versions_before = _versions_for_key(s3, bucket, key)
    assert versions_before == [live_version], (
        f"expected exactly the one freshly written version {live_version!r} before any "
        f"conditional read, ListObjectVersions reports {versions_before!r}"
    )

    # --- Leg 1: If-None-Match carrying the CURRENT ETag must be answered 304.
    not_modified = _client_error(
        lambda: s3.get_object(Bucket=bucket, Key=key, IfNoneMatch=live_etag),
        f"GetObject with IfNoneMatch set to the object's own current ETag {live_etag!r}",
    )
    nm_status = not_modified.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert nm_status == 304, (
        f"expected HTTP 304 Not Modified for an If-None-Match matching the current ETag, got "
        f"{nm_status!r}"
    )

    # --- Leg 2: a stale If-Match must be refused with 412 PreconditionFailed.
    assert _STALE_ETAG != live_etag, (
        f"the stale ETag fixture {_STALE_ETAG!r} collided with the live ETag {live_etag!r}, so "
        f"this leg cannot distinguish a stale precondition from a current one"
    )
    precondition = _client_error(
        lambda: s3.get_object(Bucket=bucket, Key=key, IfMatch=_STALE_ETAG),
        f"GetObject with the stale IfMatch {_STALE_ETAG!r} on an object whose current ETag is "
        f"{live_etag!r}",
    )
    pf_code = precondition.response.get("Error", {}).get("Code")
    pf_message = precondition.response.get("Error", {}).get("Message")
    pf_status = precondition.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert pf_code == "PreconditionFailed", (
        f"expected error code 'PreconditionFailed' for a stale If-Match on a read, got "
        f"{pf_code!r}"
    )
    assert pf_message == "At least one of the pre-conditions you specified did not hold", (
        f"expected error message 'At least one of the pre-conditions you specified did not hold' "
        f"for a stale If-Match on a read, got {pf_message!r}"
    )
    assert pf_status == 412, f"expected HTTP 412 for PreconditionFailed, got {pf_status!r}"

    # --- Effect absent: neither refusal touched the version history.
    versions_after = _versions_for_key(s3, bucket, key)
    assert versions_after == versions_before, (
        f"a refused conditional read mutated the version history: ListObjectVersions now "
        f"reports {versions_after!r}, want the unchanged {versions_before!r}"
    )

    # --- POSITIVE CONTROL: If-Match on the CURRENT ETag must be honoured and serve the payload.
    matched = s3.get_object(Bucket=bucket, Key=key, IfMatch=live_etag)
    matched_status = matched.get("ResponseMetadata", {}).get("HTTPStatusCode")
    matched_body = matched["Body"].read()
    assert matched_status == 200, (
        f"positive control: GetObject with IfMatch set to the current ETag {live_etag!r} must "
        f"return HTTP 200, got {matched_status!r}"
    )
    assert matched_body == _BODY, (
        f"positive control: GetObject with IfMatch set to the current ETag must return the exact "
        f"stored payload, got {matched_body!r}, want {_BODY!r}"
    )

    # --- POSITIVE CONTROL: the unconditional read must still return the exact payload.
    served = s3.get_object(Bucket=bucket, Key=key)
    served_body = served["Body"].read()
    assert served_body == _BODY, (
        f"positive control: the unconditional GetObject must return the exact stored payload, "
        f"got {served_body!r}, want {_BODY!r}"
    )
    assert served["ETag"] == live_etag, (
        f"positive control: the unconditional GetObject reported ETag {served['ETag']!r}, want "
        f"{live_etag!r}"
    )
    assert served.get("VersionId") == live_version, (
        f"positive control: the unconditional GetObject served version "
        f"{served.get('VersionId')!r}, want the only version {live_version!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
