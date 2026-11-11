"""conc-s3-conditional-writes-if-match-over-delete-marker-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-s3-conditional-writes-if-match-over-delete-marker-rejected"
GROUP = 'conditional-rejection'
SERVICES = ['s3']

_V1 = b"first-version"
_V2 = b"second-version-written-by-compare-and-swap-then-deleted"
_REVIVE = b"a-stale-writer-trying-to-revive-a-deleted-key"
_NO_SUCH_KEY_MSG = 'The specified key does not exist.'
_MARKER_DELETE_MSG = 'The specified key does not exist.'


def _delete_bucket(s3, bucket):
    """Abort uploads, empty every version and marker, then delete the bucket (raises if it cannot)."""
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-condw-")
    params = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; not a region pin.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn, refused="the call succeeded; AWS refuses it with a ClientError"):
    """Call fn(); return the ClientError it raised. A call that succeeds fails the check."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError(refused)


def _message(exc):
    return exc.response.get("Error", {}).get("Message")


def _all_versions(s3, bucket):
    versions, markers = [], []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        versions += page.get("Versions", [])
        markers += page.get("DeleteMarkers", [])
    return versions, markers


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """When the current version is a delete marker, If-Match PutObject and DeleteObject naming the
    hidden version's ETag fail with NoSuchKey (exact messages), adding no version and no second marker;
    before the delete the same If-Match PutObject succeeds."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    assert s3.get_bucket_versioning(Bucket=bucket).get("Status") == "Enabled", (
        "versioning did not take effect on the bucket"
    )
    key = "cas/deleted.txt"

    r1 = s3.put_object(Bucket=bucket, Key=key, Body=_V1)

    # --- POSITIVE CONTROL: If-Match with the current ETag succeeds and appends v2.
    r2 = s3.put_object(Bucket=bucket, Key=key, Body=_V2, IfMatch=r1["ETag"])
    assert r2["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"If-Match with the current ETag returned {r2['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    assert s3.get_object(Bucket=bucket, Key=key)["Body"].read() == _V2, (
        "the positive-control conditional write did not become the current version"
    )

    # --- Break exactly one thing: make a delete marker the current version.
    deleted = s3.delete_object(Bucket=bucket, Key=key)
    assert deleted.get("DeleteMarker") is True, f"setup delete created no marker: {deleted!r}"
    marker_id = deleted["VersionId"]

    put_exc = _client_error(lambda: s3.put_object(Bucket=bucket, Key=key, Body=_REVIVE,
                                                  IfMatch=r2["ETag"]),
                            f"PutObject If-Match {r2['ETag']!r} succeeded over a delete marker; "
                            "a stale writer resurrected a deleted key")
    code = put_exc.response.get("Error", {}).get("Code")
    status = put_exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "NoSuchKey", f"expected NoSuchKey for If-Match over a marker, got {code!r}"
    assert _message(put_exc) == _NO_SUCH_KEY_MSG, (
        f"expected message {_NO_SUCH_KEY_MSG!r}, got {_message(put_exc)!r}"
    )
    assert status == 404, f"expected HTTP 404, got {status!r}"

    del_exc = _client_error(lambda: s3.delete_object(Bucket=bucket, Key=key, IfMatch=r2["ETag"]),
                            f"DeleteObject If-Match {r2['ETag']!r} succeeded over a delete marker")
    del_code = del_exc.response.get("Error", {}).get("Code")
    assert del_code == "NoSuchKey", (
        f"expected NoSuchKey for a conditional delete over a marker, got {del_code!r}"
    )
    assert _message(del_exc) == _MARKER_DELETE_MSG, (
        f"expected message {_MARKER_DELETE_MSG!r} for the conditional delete, got "
        f"{_message(del_exc)!r}"
    )

    # --- Effect absent: exactly v1, v2 and the one marker; the marker is still latest.
    versions, markers = _all_versions(s3, bucket)
    ids = sorted(v["VersionId"] for v in versions)
    assert ids == sorted([r1["VersionId"], r2["VersionId"]]), (
        f"ListObjectVersions reports versions {ids!r}; want exactly v1 and v2 (no revived write)"
    )
    assert [(m["VersionId"], m["IsLatest"]) for m in markers] == [(marker_id, True)], (
        f"delete markers are {[(m['VersionId'], m['IsLatest']) for m in markers]!r}; want only "
        f"[({marker_id!r}, True)]: the conditional delete must not stack a second marker"
    )
    hidden = _client_error(lambda: s3.get_object(Bucket=bucket, Key=key),
                           "the key is readable again after refused writes")
    assert hidden.response["Error"]["Code"] == "NoSuchKey", (
        f"GetObject behind the marker returned {hidden!r}; want NoSuchKey"
    )
    assert hidden.response["Error"]["Message"] == "The specified key does not exist.", (
        f'expected the exact NoSuchKey message AWS returns, got {hidden.response["Error"]["Message"]!r}'
    )
    assert _message(hidden) == _NO_SUCH_KEY_MSG, (
        f"expected message {_NO_SUCH_KEY_MSG!r} from GetObject, got {_message(hidden)!r}"
    )
    kept = s3.get_object(Bucket=bucket, Key=key, VersionId=r2["VersionId"])["Body"].read()
    assert kept == _V2, f"v2 behind the marker now holds {kept!r}; want {_V2!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
