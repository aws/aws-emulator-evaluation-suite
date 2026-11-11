"""s3-if-none-match-star-put-is-atomic-across-a-delete-marker."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-if-none-match-star-put-is-atomic-across-a-delete-marker"
GROUP = 'conditional-rejection'
SERVICES = ['s3']

_ORIGINAL = b"the-original-version-hidden-behind-the-delete-marker"
_PAYLOAD_A = b"payload-A-written-under-if-none-match-star"
_PAYLOAD_B = b"payload-B-which-must-never-reach-the-key"


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """If-None-Match: * checks only the current version: a PUT over a delete marker succeeds, while
    the same PUT over the new live object is refused, adds no version, and leaves its bytes intact.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    assert s3.get_bucket_versioning(Bucket=bucket).get("Status") == "Enabled", (
        "versioning did not take effect on the bucket"
    )

    key = "conditional-over-marker.bin"
    original_version = s3.put_object(Bucket=bucket, Key=key, Body=_ORIGINAL)["VersionId"]
    deleted = s3.delete_object(Bucket=bucket, Key=key)
    marker_version = deleted["VersionId"]
    assert deleted.get("DeleteMarker") is True, (
        f"the setup delete did not create a marker: {deleted!r}"
    )

    # --- POSITIVE CONTROL: the conditional PUT must SUCCEED over a delete marker, because the
    # marker means the key has no current object even though it has two versions of history.
    first = s3.put_object(Bucket=bucket, Key=key, Body=_PAYLOAD_A, IfNoneMatch="*")
    assert first["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"If-None-Match:* over a delete marker was refused with "
        f"{first['ResponseMetadata']['HTTPStatusCode']!r} — the version HISTORY is being treated "
        "as object existence, so no client can ever create-if-absent a previously deleted key"
    )
    written_version = first["VersionId"]
    assert written_version not in (marker_version, original_version), (
        f"the conditional PUT reported VersionId {written_version!r}, which collides with the "
        f"delete marker {marker_version!r} or the original {original_version!r}"
    )

    # --- Break exactly one thing: now the key HAS a current object, so the identical call must
    # be refused.
    exc = _client_error(
        lambda: s3.put_object(Bucket=bucket, Key=key, Body=_PAYLOAD_B, IfNoneMatch="*")
    )
    assert exc is not None, (
        "the second identical If-None-Match:* PUT succeeded over an existing object — the "
        "condition is being ignored, so two concurrent create-if-absent writers both win and the "
        "loser's data is silently discarded"
    )
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "PreconditionFailed", (
        f"expected PreconditionFailed for If-None-Match:* over an existing object, got {code!r}"
    )
    message = exc.response.get("Error", {}).get("Message")
    assert message == "At least one of the pre-conditions you specified did not hold", (
        f"unexpected PreconditionFailed message for If-None-Match:* over an existing object: {message!r}"
    )
    assert status == 412, f"expected HTTP 412 for PreconditionFailed, got {status!r}"

    # --- Effect absent: payload B never landed, and no version was created for it.
    got = s3.get_object(Bucket=bucket, Key=key)
    body = got["Body"].read()
    assert body == _PAYLOAD_A, (
        f"the refused conditional PUT overwrote the object: it holds {body!r}, want {_PAYLOAD_A!r}"
    )
    assert got["VersionId"] == written_version, (
        f"the current version is {got['VersionId']!r}, want the first PUT's {written_version!r}"
    )

    versions, markers = _all_versions(s3, bucket)
    version_ids = sorted(v["VersionId"] for v in versions)
    assert version_ids == sorted([original_version, written_version]), (
        f"ListObjectVersions reports versions {version_ids!r}; want exactly the original and the "
        f"one conditional write, {sorted([original_version, written_version])!r} — the refused "
        "PUT created a version"
    )
    assert [m["VersionId"] for m in markers] == [marker_version], (
        f"ListObjectVersions reports delete markers {[m['VersionId'] for m in markers]!r}, want "
        f"exactly [{marker_version!r}]"
    )
    assert {v["VersionId"] for v in versions if v["IsLatest"]} == {written_version}, (
        f"the latest version is {[v['VersionId'] for v in versions if v['IsLatest']]!r}, want "
        f"[{written_version!r}]"
    )

    # --- And the original version behind the marker is still readable, untouched by any of it.
    still = s3.get_object(Bucket=bucket, Key=key, VersionId=original_version)
    assert still["Body"].read() == _ORIGINAL, (
        "the version hidden behind the delete marker no longer holds its original bytes"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
