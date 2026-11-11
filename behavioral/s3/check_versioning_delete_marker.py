"""versioning-delete-marker."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "versioning-delete-marker"
GROUP = 'versioning'
SERVICES = ['s3']

ERR_NO_SUCH_KEY = "NoSuchKey"
ERR_NO_SUCH_VERSION = "NoSuchVersion"
_NO_SUCH_VERSION_MSG = "The specified version does not exist."

_TEARDOWN_GONE = ("NoSuchBucket", "NoSuchKey")


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it.

    Only S3's own not-found codes are tolerated; any other error raises so a leaked bucket is visible.
    """
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _TEARDOWN_GONE:
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


def _err(fn):
    """Call fn(); return the ClientError response it raises. An unexpected SUCCESS raises, so a
    target that serves a deleted key is not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _assert_error(resp, what, codes, status, field=None, value=None, exact=False):
    """Grade a refusal on code + HTTP status class + non-empty message (+ the structured id field);
    return its Error. The exact status is graded (exact=True) only where it is the signal: GET of
    an object."""
    err = resp.get("Error", {})
    got_status = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert err.get("Code") in codes, f"{what}: expected code in {codes}, got {err.get('Code')!r}"
    if exact:
        assert got_status == status, f"{what}: expected HTTP {status}, got {got_status!r}"
    else:
        assert isinstance(got_status, int) and got_status // 100 == status // 100, (
            f"{what}: expected HTTP {status // 100}xx, got {got_status!r}"
        )
    assert err.get("Message"), f"{what}: expected a non-empty error message, got {err.get('Message')!r}"
    if field is not None:
        assert err.get(field) == value, f"{what}: expected Error.{field} {value!r}, got {err.get(field)!r}"
    return err


def _all_versions(s3, bucket):
    """Fully paginated (Versions, DeleteMarkers) for a bucket."""
    versions, markers = [], []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        versions += page.get("Versions", [])
        markers += page.get("DeleteMarkers", [])
    return versions, markers


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A delete marker hides a key without destroying it: the data version survives, drops out of
    IsLatest, and a bare GET 404s until the marker itself is deleted, which restores the bytes."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    key = "del-marker-key"
    data_version = s3.put_object(Bucket=bucket, Key=key, Body=b"content")["VersionId"]
    assert data_version and data_version != "null", (
        f"a PUT into a versioned bucket returned VersionId {data_version!r}"
    )

    del_resp = s3.delete_object(Bucket=bucket, Key=key)
    assert del_resp.get("DeleteMarker") is True, f"DeleteMarker not set in response: {del_resp.get('DeleteMarker')!r}"
    marker_version = del_resp.get("VersionId")
    assert marker_version and marker_version != data_version, (
        f"delete marker VersionId {marker_version!r} must exist and differ from the data version {data_version!r}"
    )

    hidden = _assert_error(
        _err(lambda: s3.get_object(Bucket=bucket, Key=key)),
        "GetObject behind the delete marker", (ERR_NO_SUCH_KEY,), 404, exact=True,
    )
    assert hidden.get("Message") == "The specified key does not exist.", (
        f"GetObject behind the delete marker: expected the exact NoSuchKey message, got {hidden!r}"
    )

    # The marker is a version, not a deletion — list_object_versions must show both: the data
    # version demoted from IsLatest, and the marker installed as IsLatest in its place.
    versions, markers = _all_versions(s3, bucket)
    by_version = {v["VersionId"]: v for v in versions}
    by_marker = {m["VersionId"]: m for m in markers}
    assert data_version in by_version, (
        f"data version {data_version!r} missing from ListObjectVersions: {sorted(by_version)!r}"
    )
    assert by_version[data_version]["IsLatest"] is False, (
        f"data version is still IsLatest after the delete: {by_version[data_version]!r}"
    )
    assert marker_version in by_marker, (
        f"delete marker {marker_version!r} missing from ListObjectVersions: {sorted(by_marker)!r}"
    )
    assert by_marker[marker_version]["IsLatest"] is True, (
        f"delete marker is not IsLatest: {by_marker[marker_version]!r}"
    )

    # The data was hidden, not destroyed: a version-pinned read still returns the original bytes.
    pinned_body = s3.get_object(Bucket=bucket, Key=key, VersionId=data_version)["Body"].read()
    assert pinned_body == b"content", (
        f"version-pinned read returned {pinned_body!r}, want b'content' — the delete marker "
        "destroyed the underlying version instead of hiding it"
    )

    # Deleting the marker itself (not the data) restores the plain read.
    s3.delete_object(Bucket=bucket, Key=key, VersionId=marker_version)
    restored = s3.get_object(Bucket=bucket, Key=key)
    assert restored["Body"].read() == b"content", "deleting the delete marker did not restore the bytes"
    assert restored["VersionId"] == data_version, (
        f"the restored read is version {restored['VersionId']!r}, want the original {data_version!r}"
    )

    # Permanently deleting the data version destroys it: unreadable, unlisted, uncopyable.
    s3.delete_object(Bucket=bucket, Key=key, VersionId=data_version)
    gone = _assert_error(
        _err(lambda: s3.get_object(Bucket=bucket, Key=key, VersionId=data_version)),
        "GetObject of the permanently deleted version", (ERR_NO_SUCH_VERSION,), 404, exact=True,
    )
    assert gone.get("Message") == _NO_SUCH_VERSION_MSG, (
        f"GetObject of the permanently deleted version: expected {_NO_SUCH_VERSION_MSG!r}, got {gone!r}"
    )
    page = s3.list_object_versions(Bucket=bucket, Prefix=key)
    left = [v["VersionId"] for v in page.get("Versions", []) + page.get("DeleteMarkers", []) if v["Key"] == key]
    assert not left, f"ListObjectVersions still lists {len(left)} version(s)/marker(s) for the key after permanent delete"
    uncopied = _assert_error(
        _err(lambda: s3.copy_object(
            Bucket=bucket, Key=key + "-copy",
            CopySource={"Bucket": bucket, "Key": key, "VersionId": data_version},
        )),
        "CopyObject from the permanently deleted version", (ERR_NO_SUCH_VERSION,), 404,
    )
    assert uncopied.get("Message") == _NO_SUCH_VERSION_MSG, (
        f"CopyObject from the permanently deleted version: expected {_NO_SUCH_VERSION_MSG!r}, got {uncopied!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
