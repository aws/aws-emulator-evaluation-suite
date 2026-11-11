"""s3-delete-marker-hides-the-object-while-the-version-still-returns-its-bytes."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-delete-marker-hides-the-object-while-the-version-still-returns-its-bytes"
GROUP = 'versioning-semantics'
SERVICES = ['s3']

_PAYLOAD = b"the-bytes-a-delete-marker-must-hide-without-destroying" * 8


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


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


def _all_versions(s3, bucket):
    """Fully paginated (Versions, DeleteMarkers) for a bucket."""
    versions, markers = [], []
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        versions += page.get("Versions", [])
        markers += page.get("DeleteMarkers", [])
    return versions, markers


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """An unversioned delete adds a marker: GET/HEAD 404 (HEAD flags the marker), the pinned GET
    returns the bytes, ListObjectsV2 omits the key, ListObjectVersions shows the marker latest,
    GET on the marker is 405, and deleting the marker restores the bytes.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(
        Bucket=bucket, VersioningConfiguration={"Status": "Enabled"}
    )
    status = s3.get_bucket_versioning(Bucket=bucket).get("Status")
    assert status == "Enabled", f"versioning did not take effect: Status is {status!r}"

    key = "hidden-not-destroyed.bin"
    data_version = s3.put_object(Bucket=bucket, Key=key, Body=_PAYLOAD)["VersionId"]
    assert data_version and data_version != "null", (
        f"a PUT into a versioned bucket returned VersionId {data_version!r}"
    )

    # --- One mutation: an unversioned delete, which must create a marker rather than remove data.
    deleted = s3.delete_object(Bucket=bucket, Key=key)
    assert deleted.get("DeleteMarker") is True, (
        f"the unversioned delete on a versioned bucket reported DeleteMarker "
        f"{deleted.get('DeleteMarker')!r}; it must create a marker, not delete the object"
    )
    marker_version = deleted.get("VersionId")
    assert marker_version and marker_version != data_version, (
        f"the delete marker's VersionId is {marker_version!r}, which must exist and must differ "
        f"from the data version {data_version!r}"
    )

    # --- Read 1: the plain GET is hidden by the marker.
    hidden = _client_error(lambda: s3.get_object(Bucket=bucket, Key=key))
    assert hidden is not None, (
        "GetObject still returns the object after a delete marker was placed over it"
    )
    assert hidden.response["Error"]["Code"] == "NoSuchKey", (
        f"expected NoSuchKey for a key hidden by a delete marker, got "
        f"{hidden.response['Error']['Code']!r}"
    )
    assert hidden.response["Error"].get("Message") == "The specified key does not exist.", (
        f"unexpected NoSuchKey message for a key hidden by a delete marker: "
        f"{hidden.response['Error'].get('Message')!r}"
    )
    assert hidden.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"expected HTTP 404, got {hidden.response['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    # --- Read 1b: the plain HEAD also 404s, but S3 says WHY in a header — the response carries
    # x-amz-delete-marker: true, which is how a client distinguishes "hidden by a marker" from
    # "never existed". An emulator that models this as plain absence omits the header.
    head_hidden = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key))
    assert head_hidden is not None, "HeadObject still returns the object hidden by a delete marker"
    head_meta = head_hidden.response["ResponseMetadata"]
    assert head_meta["HTTPStatusCode"] == 404, (
        f"expected HTTP 404 for a HEAD of a key hidden by a marker, got "
        f"{head_meta['HTTPStatusCode']!r}"
    )
    assert head_meta["HTTPHeaders"].get("x-amz-delete-marker") == "true", (
        f"the 404 for a key hidden by a delete marker must carry x-amz-delete-marker: true; the "
        f"response headers were {head_meta['HTTPHeaders']!r}"
    )

    # --- Read 2: the version-pinned GET returns the exact bytes. The data was never destroyed.
    pinned = s3.get_object(Bucket=bucket, Key=key, VersionId=data_version)
    pinned_body = pinned["Body"].read()
    assert pinned_body == _PAYLOAD, (
        f"the version-pinned read returned {len(pinned_body)} bytes, want {len(_PAYLOAD)} — the "
        "delete marker destroyed the underlying version instead of hiding it"
    )
    assert pinned["VersionId"] == data_version, (
        f"the version-pinned read echoed VersionId {pinned['VersionId']!r}, want {data_version!r}"
    )

    # --- Read 3: ListObjectsV2 omits the key entirely.
    listed_keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        listed_keys += [o["Key"] for o in page.get("Contents", [])]
    assert key not in listed_keys, (
        f"ListObjectsV2 still shows the key hidden by a delete marker: {sorted(listed_keys)!r}"
    )

    # --- Read 4: ListObjectVersions shows both, with the marker as IsLatest.
    versions, markers = _all_versions(s3, bucket)
    by_marker = {m["VersionId"]: m for m in markers}
    by_version = {v["VersionId"]: v for v in versions}
    assert marker_version in by_marker, (
        f"the delete marker {marker_version!r} is not in ListObjectVersions' DeleteMarkers: "
        f"{sorted(by_marker)!r}"
    )
    assert by_marker[marker_version]["IsLatest"] is True, (
        f"the delete marker is not IsLatest: {by_marker[marker_version]!r}"
    )
    assert data_version in by_version, (
        f"the data version {data_version!r} is not in ListObjectVersions' Versions: "
        f"{sorted(by_version)!r}"
    )
    assert by_version[data_version]["IsLatest"] is False, (
        f"the hidden data version is still IsLatest: {by_version[data_version]!r}"
    )
    assert by_version[data_version]["Size"] == len(_PAYLOAD), (
        f"the hidden data version reports Size {by_version[data_version]['Size']!r}, want "
        f"{len(_PAYLOAD)}"
    )

    # --- Read 5: GET on the marker version is 405 MethodNotAllowed with Allow: DELETE, not
    # NotFound: the marker exists, and DELETE is the only verb it accepts.
    on_marker = _client_error(
        lambda: s3.get_object(Bucket=bucket, Key=key, VersionId=marker_version)
    )
    assert on_marker is not None, (
        "GetObject on the delete-marker version returned content; a marker has none"
    )
    marker_meta = on_marker.response["ResponseMetadata"]
    assert on_marker.response["Error"]["Code"] == "MethodNotAllowed", (
        f"expected MethodNotAllowed for a GET of the delete-marker version, got "
        f"{on_marker.response['Error']['Code']!r} — a marker that reports NoSuchVersion is being "
        "modelled as absence rather than as a version"
    )
    assert on_marker.response["Error"].get("Message") == (
        "The specified method is not allowed against this resource."
    ), (
        f"unexpected MethodNotAllowed message for a GET of the delete-marker version: "
        f"{on_marker.response['Error'].get('Message')!r}"
    )
    assert marker_meta["HTTPStatusCode"] == 405, (
        f"expected HTTP 405 for a GET of the delete-marker version, got "
        f"{marker_meta['HTTPStatusCode']!r}"
    )
    assert marker_meta["HTTPHeaders"].get("allow") == "DELETE", (
        f"the 405 must advertise Allow: DELETE — the marker's only legal verb; headers were "
        f"{marker_meta['HTTPHeaders']!r}"
    )

    # --- Read 6: deleting the MARKER by version id restores the key's bytes.
    s3.delete_object(Bucket=bucket, Key=key, VersionId=marker_version)
    restored = s3.get_object(Bucket=bucket, Key=key)
    restored_body = restored["Body"].read()
    assert restored_body == _PAYLOAD, (
        f"deleting the delete marker did not restore the bytes: got {len(restored_body)} bytes, "
        f"want {len(_PAYLOAD)}"
    )
    assert restored["VersionId"] == data_version, (
        f"the restored read is version {restored['VersionId']!r}, want the original "
        f"{data_version!r}"
    )
    after_versions, after_markers = _all_versions(s3, bucket)
    assert [m["VersionId"] for m in after_markers] == [], (
        f"delete markers survive after deleting the only one: {after_markers!r}"
    )
    assert [v["VersionId"] for v in after_versions] == [data_version], (
        f"ListObjectVersions now reports {[v['VersionId'] for v in after_versions]!r}, want "
        f"exactly [{data_version!r}]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
