"""s3-delete-object-with-a-stale-if-match-etag-is-refused-and-the-object-survives."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-delete-object-with-a-stale-if-match-etag-is-refused-and-the-object-survives"
GROUP = 'conditional-rejection'
SERVICES = ['s3']

_V1 = b"version-one-bytes-that-must-not-be-what-survives"
_V2 = b"version-two-bytes-and-these-are-the-current-content-of-the-key"


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A DeleteObject whose IfMatch is the overwritten version's ETag fails 412 and leaves the
    current bytes; the same delete with the current ETag succeeds as the positive control.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "conditionally-deleted.bin"

    v1_etag = s3.put_object(Bucket=bucket, Key=key, Body=_V1)["ETag"]
    put2 = s3.put_object(Bucket=bucket, Key=key, Body=_V2)
    v2_etag = put2["ETag"]
    assert v1_etag != v2_etag, (
        f"the overwrite produced the same ETag {v2_etag!r} for different bytes, so this check "
        "cannot distinguish a stale ETag from a current one"
    )

    # --- Break exactly one thing: hand the delete the ETag of the version it replaced.
    exc = _client_error(lambda: s3.delete_object(Bucket=bucket, Key=key, IfMatch=v1_etag))
    assert exc is not None, (
        f"DeleteObject with the stale ETag {v1_etag!r} succeeded on a key whose current ETag is "
        f"{v2_etag!r} — IfMatch is being ignored, so every optimistic-concurrency delete in this "
        "emulator silently destroys a version the caller never saw"
    )
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "PreconditionFailed", (
        f"expected PreconditionFailed for a stale IfMatch on a delete, got {code!r}"
    )
    message = exc.response.get("Error", {}).get("Message")
    assert message == "At least one of the pre-conditions you specified did not hold", (
        f"unexpected PreconditionFailed message for a stale IfMatch on a delete: {message!r}"
    )
    assert status == 412, f"expected HTTP 412 for PreconditionFailed, got {status!r}"

    # --- Effect absent: the object is untouched, by bytes and by ETag.
    got = s3.get_object(Bucket=bucket, Key=key)
    body = got["Body"].read()
    assert body == _V2, (
        f"the refused conditional delete changed the object: it now holds {body!r}, want {_V2!r}"
    )
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ETag"] == v2_etag, (
        f"the object's ETag is now {head['ETag']!r}, want the untouched {v2_etag!r}"
    )
    assert head["ContentLength"] == len(_V2), (
        f"the object is {head['ContentLength']} bytes, want {len(_V2)}"
    )
    listed = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        listed += [o["Key"] for o in page.get("Contents", [])]
    assert listed == [key], (
        f"after the refused delete the bucket lists {listed!r}, want exactly [{key!r}]"
    )

    # --- POSITIVE CONTROL: the identical call with the CURRENT ETag must delete the key.
    removed = s3.delete_object(Bucket=bucket, Key=key, IfMatch=v2_etag)
    assert removed["ResponseMetadata"]["HTTPStatusCode"] == 204, (
        f"the conditional delete with the current ETag returned "
        f"{removed['ResponseMetadata']['HTTPStatusCode']!r}, expected 204"
    )
    gone = _client_error(lambda: s3.head_object(Bucket=bucket, Key=key))
    assert gone is not None, (
        "the conditional delete with the current ETag reported success but the key is still there"
    )
    assert gone.response["ResponseMetadata"]["HTTPStatusCode"] == 404, (
        f"HeadObject after the successful conditional delete returned "
        f"{gone.response['ResponseMetadata']['HTTPStatusCode']!r}, expected 404"
    )
    empty = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        empty += [o["Key"] for o in page.get("Contents", [])]
    assert empty == [], f"the bucket still lists {empty!r} after the successful delete"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
