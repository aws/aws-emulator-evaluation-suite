"""delete-objects-partial-failure."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-objects-partial-failure"
GROUP = 'lifecycle'
SERVICES = ['s3']

def _error_code(fn, what):
    """Call fn(); return botocore Error.Code of the ClientError it raised. A success raises AssertionError."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"{what} succeeded; expected a refusal")


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


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteObjects processes a mixed batch per-key: valid deletes succeed while a bogus VersionId reports a per-key error."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    good_key = "batch-good.txt"
    put_resp = s3.put_object(Bucket=bucket, Key=good_key, Body=b"payload")
    real_version = put_resp["VersionId"]
    bad_key = "batch-bad.txt"
    bad_put_resp = s3.put_object(Bucket=bucket, Key=bad_key, Body=b"payload2")
    bad_real_version = bad_put_resp["VersionId"]
    bogus_version = real_version[:-1] + ("A" if real_version[-1] != "A" else "B")

    resp = s3.delete_objects(
        Bucket=bucket,
        Delete={
            "Objects": [
                {"Key": good_key, "VersionId": real_version},
                {"Key": bad_key, "VersionId": bogus_version},
            ],
            "Quiet": False,
        },
    )

    deleted_keys = {d["Key"] for d in resp.get("Deleted", [])}
    errors = {e["Key"]: e for e in resp.get("Errors", [])}
    assert good_key in deleted_keys, f"expected {good_key!r} in Deleted, got {resp.get('Deleted')}"
    bad_err = errors.get(bad_key, {})
    assert bad_err.get("Code") == "NoSuchVersion", f"expected NoSuchVersion error for {bad_key!r}, got {errors}"
    assert bad_err.get("Message") == "The specified version does not exist.", bad_err.get("Message")

    # independent read at the destination: the deleted version is actually gone, not just reported gone
    # HeadObject answers with no body, so there is no service message to grade beyond the status code
    gone_code = _error_code(
        lambda: s3.head_object(Bucket=bucket, Key=good_key, VersionId=real_version),
        f"HeadObject of deleted version {real_version!r}",
    )
    assert gone_code == "404", f"expected {good_key!r} version {real_version!r} gone (404), got {gone_code!r}"

    # independent read: the per-key error on bad_key actually withheld the delete of its real version
    survivor = s3.head_object(Bucket=bucket, Key=bad_key, VersionId=bad_real_version)
    assert survivor["VersionId"] == bad_real_version, (
        f"expected {bad_key!r} version {bad_real_version!r} untouched by the failed delete, "
        f"got VersionId={survivor.get('VersionId')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
