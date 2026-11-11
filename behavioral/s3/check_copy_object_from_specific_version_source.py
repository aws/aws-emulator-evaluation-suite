"""copy-object-from-specific-version-source."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "copy-object-from-specific-version-source"
GROUP = 'copy'
SERVICES = ['s3']

_NO_SUCH_VERSION_MSG = 'The specified version does not exist.'


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


def _client_error(fn, refused="the call succeeded; AWS refuses it with a ClientError"):
    """Call fn(); return the ClientError it raised. A call that succeeds fails the check."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError(refused)


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CopyObject with a versioned CopySource copies THAT version, not the current one.

    A CopySource carrying ?versionId=<old> is how a caller restores history, and the response echoes
    x-amz-copy-source-version-id; copying the latest version instead silently undoes a rollback.
    """
    s3 = ctx.client("s3")
    src = _new_bucket(ctx, s3)
    dst = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=src, VersioningConfiguration={"Status": "Enabled"})
    key = "history.txt"

    v1 = s3.put_object(Bucket=src, Key=key, Body=b"one")["VersionId"]
    v2 = s3.put_object(Bucket=src, Key=key, Body=b"two")["VersionId"]
    v3 = s3.put_object(Bucket=src, Key=key, Body=b"three")["VersionId"]
    assert len({v1, v2, v3}) == 3, f"expected three distinct version ids, got {[v1, v2, v3]}"
    assert s3.get_object(Bucket=src, Key=key)["Body"].read() == b"three", "v3 must be current"

    # --- The behavior under test: copy the OLDEST version while a newer one is current.
    copied = s3.copy_object(
        Bucket=dst,
        Key="restored-v1.txt",
        CopySource={"Bucket": src, "Key": key, "VersionId": v1},
    )
    assert copied.get("CopySourceVersionId") == v1, (
        f"CopyObject must echo CopySourceVersionId={v1!r} so the caller can confirm which version "
        f"was read, got {copied.get('CopySourceVersionId')!r}"
    )
    body = s3.get_object(Bucket=dst, Key="restored-v1.txt")["Body"].read()
    assert body == b"one", (
        f"copying CopySource versionId={v1} must yield b'one'; got {body!r} — the versionId was "
        "ignored and the current version was copied instead"
    )

    # --- The middle version resolves independently, so this is not an off-by-one that happens to
    # land on the first version.
    copied2 = s3.copy_object(
        Bucket=dst,
        Key="restored-v2.txt",
        CopySource={"Bucket": src, "Key": key, "VersionId": v2},
    )
    assert copied2.get("CopySourceVersionId") == v2, (
        f"CopyObject must echo CopySourceVersionId={v2!r} for the middle version, got "
        f"{copied2.get('CopySourceVersionId')!r}"
    )
    assert s3.get_object(Bucket=dst, Key="restored-v2.txt")["Body"].read() == b"two", (
        "copying the middle version must yield b'two'"
    )

    # --- Control: no versionId means the current version.
    copied3 = s3.copy_object(
        Bucket=dst, Key="restored-current.txt", CopySource={"Bucket": src, "Key": key}
    )
    assert copied3.get("CopySourceVersionId") == v3, (
        f"an unversioned CopySource must resolve to the current version {v3!r}, got "
        f"{copied3.get('CopySourceVersionId')!r}"
    )
    current_body = s3.get_object(Bucket=dst, Key="restored-current.txt")["Body"].read()
    assert current_body == b"three", (
        f"copying an unversioned CopySource must yield b'three' (the current version); got "
        f"{current_body!r}"
    )

    # --- Break exactly one thing: a well-formed source version id that no longer exists.
    # The CopySource resolution path is a different code path from GetObject in every
    # implementation.
    s3.delete_object(Bucket=src, Key=key, VersionId=v2)
    exc = _client_error(
        lambda: s3.copy_object(
            Bucket=dst,
            Key="restored-gone.txt",
            CopySource={"Bucket": src, "Key": key, "VersionId": v2},
        ),
        f"copying from the permanently deleted version {v2} succeeded; the source version id is "
        "not being resolved",
    )
    code = exc.response.get("Error", {}).get("Code")
    assert code == "NoSuchVersion", (
        f"expected NoSuchVersion for a deleted CopySource version, got {code!r}"
    )
    message = exc.response.get("Error", {}).get("Message")
    assert message == _NO_SUCH_VERSION_MSG, (
        f"expected message {_NO_SUCH_VERSION_MSG!r}, got {message!r}"
    )

    # --- Effect absent: the failed copy created no destination object.
    exc = _client_error(lambda: s3.head_object(Bucket=dst, Key="restored-gone.txt"),
                        "the failed versioned copy created a destination object anyway")
    listed = {
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=dst)
        for o in page.get("Contents", [])
    }
    assert listed == {"restored-v1.txt", "restored-v2.txt", "restored-current.txt"}, (
        f"unexpected destination contents: {sorted(listed)}"
    )

    # --- Effect absent on the source, and control still works: deleting v2 and the failed copy
    # left v1 and v3 alone.
    v1_body = s3.get_object(Bucket=src, Key=key, VersionId=v1)["Body"].read()
    assert v1_body == b"one", (
        f"deleting v2 must not disturb v1's bytes; expected b'one', got {v1_body!r}"
    )
    src_current_body = s3.get_object(Bucket=src, Key=key)["Body"].read()
    assert src_current_body == b"three", (
        f"deleting v2 must not disturb the current version's bytes; expected b'three', got "
        f"{src_current_body!r}"
    )
    assert s3.get_object(Bucket=dst, Key="restored-v2.txt")["Body"].read() == b"two", (
        "an already-copied object must survive the deletion of its source version"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
