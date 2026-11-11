"""head-object-on-delete-marker-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "head-object-on-delete-marker-rejected"
GROUP = 'versioning'
SERVICES = ['s3']


# ===== helpers (self-contained) =====
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
# ===== end helpers =====


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A delete marker is reported by headers: unversioned HEAD/GET are 404, addressed by version id they
    are 405 with allow: DELETE; a never-existed key carries no marker header. The listing split and
    resurrection by deleting the marker are asserted too.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    key = "marked.txt"
    body = b"still-here"
    v1 = s3.put_object(Bucket=bucket, Key=key, Body=body)["VersionId"]

    # --- Control before the delete: HEAD is a plain 200.
    assert s3.head_object(Bucket=bucket, Key=key)["ContentLength"] == len(body)

    # --- Break exactly one thing: a versioned delete, which writes a marker.
    del_resp = s3.delete_object(Bucket=bucket, Key=key)
    assert del_resp.get("DeleteMarker") is True, (
        f"a versioned delete must report DeleteMarker=True, got {del_resp.get('DeleteMarker')!r}"
    )
    marker_id = del_resp["VersionId"]
    assert marker_id and marker_id != v1, (
        f"the delete marker needs its own VersionId distinct from {v1!r}, got {marker_id!r}"
    )

    # --- HEAD on the delete-marked KEY (unversioned): 404, but a 404 that says WHY. The
    # resurrect-vs-create distinction lives in the headers, not the status code.
    exc = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key))
    assert exc is not None, "HeadObject on a delete-marked key succeeded; the marker is not honoured"
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert status == 404, (
        f"HeadObject on the delete-marked key (no VersionId) must be 404, got {status}; the 405 "
        "belongs to the version-addressed form asserted below"
    )
    headers = exc.response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
    assert headers.get("x-amz-delete-marker") == "true", (
        f"the 404 must carry x-amz-delete-marker: true — that header is the ONLY thing separating "
        f'"the latest version is a delete marker" from "this key never existed", since both are '
        f"404 — got {headers.get('x-amz-delete-marker')!r}"
    )
    assert headers.get("x-amz-version-id") == marker_id, (
        f"the 404 must report the marker's version id {marker_id!r}, got "
        f"{headers.get('x-amz-version-id')!r}"
    )
    assert "allow" not in headers, (
        f"the unversioned 404 must NOT carry an allow header; that belongs to the 405, got "
        f"{headers.get('allow')!r}"
    )

    # --- HEAD on the MARKER ITSELF, addressed by version id: 405 MethodNotAllowed, because a
    # delete marker is not an object and the only method it accepts is DELETE.
    exc = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key, VersionId=marker_id))
    assert exc is not None, (
        "HeadObject on a delete marker addressed by VersionId succeeded; a delete marker has no "
        "retrievable representation"
    )
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert status == 405, (
        f"HeadObject(VersionId=<delete marker>) must be 405 MethodNotAllowed, got {status}; "
        "answering 404 here means the emulator cannot distinguish a marker that exists from a "
        "version that does not, and answering 200 means it serves a marker as an object"
    )
    headers = exc.response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
    assert headers.get("allow") == "DELETE", (
        f"the 405 must advertise the one permitted method with allow: DELETE, got "
        f"{headers.get('allow')!r} — that header is how a client learns the marker can only be "
        f"removed, never read"
    )
    assert headers.get("x-amz-delete-marker") == "true", (
        f"the 405 must also carry x-amz-delete-marker: true, got "
        f"{headers.get('x-amz-delete-marker')!r}"
    )
    assert headers.get("x-amz-version-id") == marker_id, (
        f"the 405 must echo the addressed version id {marker_id!r}, got "
        f"{headers.get('x-amz-version-id')!r}"
    )
    assert "last-modified" in headers, (
        "the 405 carries the marker's last-modified: S3 knows the marker exists and when it was "
        "written, it just refuses to serve it as an object"
    )

    # --- GET on the marker by version id: the same 405, with the error CODE spelled out (a GET
    # has a response body, so botocore surfaces MethodNotAllowed instead of the bare status).
    exc = _client_error(lambda: s3.get_object(Bucket=bucket, Key=key, VersionId=marker_id))
    assert exc is not None, "GetObject on a delete marker addressed by VersionId succeeded"
    assert exc.response.get("Error", {}).get("Code") == "MethodNotAllowed", (
        f"GetObject(VersionId=<delete marker>) must be MethodNotAllowed, got "
        f"{exc.response.get('Error', {}).get('Code')!r}"
    )
    assert exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 405, (
        exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    )
    assert (
        exc.response.get("ResponseMetadata", {}).get("HTTPHeaders", {}).get("allow") == "DELETE"
    ), "the GET 405 must advertise allow: DELETE too"
    message = exc.response.get("Error", {}).get("Message")
    assert message == "The specified method is not allowed against this resource.", message

    # --- GET on the delete-marked KEY (unversioned): 404 NoSuchKey, with the marker headers.
    exc = _client_error(lambda: s3.get_object(Bucket=bucket, Key=key))
    assert exc is not None, "GetObject on a delete-marked key succeeded"
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "NoSuchKey", f"expected NoSuchKey from GetObject on a delete marker, got {code!r}"
    assert status == 404, f"expected HTTP 404 from GetObject on a delete marker, got {status!r}"
    message = exc.response.get("Error", {}).get("Message")
    assert message == "The specified key does not exist.", message
    headers = exc.response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
    assert headers.get("x-amz-delete-marker") == "true", (
        "GetObject's 404 on a delete marker must also carry x-amz-delete-marker: true, got "
        f"{headers.get('x-amz-delete-marker')!r}"
    )

    # --- Listing split: the flat listing hides the key, the version listing shows both entries.
    flat = {
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
        for o in page.get("Contents", [])
    }
    assert key not in flat, f"a delete-marked key must not appear in ListObjectsV2, got {sorted(flat)}"
    versions_resp = s3.list_object_versions(Bucket=bucket, Prefix=key)
    markers = versions_resp.get("DeleteMarkers", [])
    data_versions = versions_resp.get("Versions", [])
    assert [m["VersionId"] for m in markers] == [marker_id], (
        f"expected exactly the marker {marker_id!r} in DeleteMarkers, got {markers!r}"
    )
    assert markers[0]["IsLatest"] is True, "the delete marker must be the latest version"
    assert [v["VersionId"] for v in data_versions] == [v1], (
        f"expected the data version {v1!r} to survive, got {data_versions!r}"
    )
    assert data_versions[0]["IsLatest"] is False, "the data version must no longer be latest"

    # --- Effect absent: the data was NOT destroyed. Reading it by version id still works.
    by_version = s3.get_object(Bucket=bucket, Key=key, VersionId=v1)
    assert by_version["Body"].read() == body, "the shadowed version's body changed"
    assert s3.head_object(Bucket=bucket, Key=key, VersionId=v1)["ContentLength"] == len(body)

    # --- Control still works: removing the marker resurrects the key.
    s3.delete_object(Bucket=bucket, Key=key, VersionId=marker_id)
    assert s3.get_object(Bucket=bucket, Key=key)["Body"].read() == body, (
        "deleting the delete marker must resurrect the previous version"
    )
    flat_after = {
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
        for o in page.get("Contents", [])
    }
    assert flat_after == {key}, f"the resurrected key must be listed again, got {sorted(flat_after)}"

    # --- A key that genuinely never existed is a plain 404 with NO marker header — the contrast
    # that makes the 405 meaningful.
    exc = _client_error(lambda: s3.head_object(Bucket=bucket, Key="never-existed.txt"))
    assert exc is not None, "HeadObject on an absent key succeeded"
    assert exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode") == 404, (
        "a key that never existed must be 404, not 405"
    )
    headers = exc.response.get("ResponseMetadata", {}).get("HTTPHeaders", {})
    assert "x-amz-delete-marker" not in headers, (
        f"a never-existed key must not report x-amz-delete-marker, got {headers.get('x-amz-delete-marker')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
