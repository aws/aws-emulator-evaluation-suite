"""delete-objects-exceeds-max-keys-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-objects-exceeds-max-keys-rejected"
GROUP = 'errors'
SERVICES = ['s3']

_MAX_KEYS = 1000


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
        # us-east-1 is S3's default region: CreateBucket rejects an explicit
        # LocationConstraint there, so it must be omitted rather than passed.
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _client_error(fn, what):
    """Call fn(); return the ClientError it raised. A success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"{what} succeeded; expected a refusal")
# ===== end helpers =====


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteObjects caps a request at 1000 keys: 1000 is accepted, 1001 is MalformedXML and deletes nothing.

    The over-cap request is refused whole, so not one of its entries is applied: deleting entries before
    noticing the 1001st would be data loss no error code can undo.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    # Real objects that must survive the rejected request. Non-existent filler keys make the
    # 1000/1001-entry payloads cheap: DeleteObjects reports absent keys as successfully deleted.
    real_keys = [f"real/keep-{i}.txt" for i in range(3)]
    for k in real_keys:
        s3.put_object(Bucket=bucket, Key=k, Body=b"keep-me")

    def _entries(n):
        """n Object entries: the 3 real keys first, then non-existent filler up to n."""
        keys = list(real_keys) + [f"filler/absent-{i}.txt" for i in range(n - len(real_keys))]
        assert len(keys) == n
        return [{"Key": k} for k in keys]

    # --- Break exactly one thing: one entry over the cap.
    over = _entries(_MAX_KEYS + 1)
    exc = _client_error(
        lambda: s3.delete_objects(Bucket=bucket, Delete={"Objects": over, "Quiet": True}),
        f"DeleteObjects with {_MAX_KEYS + 1} entries (the {_MAX_KEYS}-key request cap)",
    )
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "MalformedXML", (
        f"expected MalformedXML for an over-cap DeleteObjects request, got {code!r}"
    )
    assert exc.response.get("Error", {}).get("Message") == (
        "The XML you provided was not well-formed or did not validate against our published schema"
    ), exc.response.get("Error")
    assert status == 400, f"expected HTTP 400 for an over-cap DeleteObjects request, got {status!r}"

    # --- Effect absent, and this is the whole point: the request is refused as a unit, so the
    # 3 real keys it named are untouched. A per-entry emulator fails here, not above.
    surviving = {
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
        for o in page.get("Contents", [])
    }
    assert surviving == set(real_keys), (
        f"an over-cap DeleteObjects must delete NOTHING; expected {sorted(real_keys)} to survive, "
        f"bucket now holds {sorted(surviving)} — the request was applied entry-by-entry before "
        "failing, which is unrecoverable data loss"
    )
    for k in real_keys:
        assert s3.get_object(Bucket=bucket, Key=k)["Body"].read() == b"keep-me"

    # --- Control: exactly at the cap is accepted, and it really deletes.
    at_cap = _entries(_MAX_KEYS)
    resp = s3.delete_objects(Bucket=bucket, Delete={"Objects": at_cap, "Quiet": False})
    errors = resp.get("Errors", [])
    assert errors == [], f"a {_MAX_KEYS}-entry DeleteObjects reported per-key errors: {errors!r}"
    deleted = {d["Key"] for d in resp.get("Deleted", [])}
    assert set(real_keys) <= deleted, (
        f"expected the real keys {sorted(real_keys)} in Deleted, got {len(deleted)} entries "
        f"missing {sorted(set(real_keys) - deleted)}"
    )
    assert len(deleted) == _MAX_KEYS, (
        f"a non-quiet {_MAX_KEYS}-entry delete must report all {_MAX_KEYS} keys as deleted "
        f"(absent keys included), got {len(deleted)}"
    )

    # --- Effect present for the accepted request: the bucket is now empty.
    remaining = {
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
        for o in page.get("Contents", [])
    }
    assert remaining == set(), f"expected an empty bucket after the at-cap delete, got {sorted(remaining)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
