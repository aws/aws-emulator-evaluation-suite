"""put-object-if-none-match-precondition."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "put-object-if-none-match-precondition"
GROUP = 'conditional'
SERVICES = ['s3']


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; raises unless gone."""
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


def _err_code(fn):
    """Call fn(); return its botocore (code, message) if a ClientError is raised. An unexpected
    SUCCESS raises, because an emulator ACCEPTING a call real AWS refuses is the strongest signal
    available."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObject with If-None-Match: * succeeds on an absent key, fails with PreconditionFailed and its
    exact message once the key exists (leaving the object unchanged), and succeeds again after the key is
    deleted."""
    s3 = ctx.client("s3")
    name = _new_bucket(ctx, s3)
    key = "conditional.txt"

    # --- Positive control: no current object yet, so If-None-Match: * must be honored.
    created = s3.put_object(Bucket=name, Key=key, Body=b"original", IfNoneMatch="*")
    status = created["ResponseMetadata"]["HTTPStatusCode"]
    assert status == 200, f"expected the create-if-absent PUT to succeed with 200, got {status!r}"

    # --- Break exactly one thing: the key now has a current object.
    code = _err_code(lambda: s3.put_object(Bucket=name, Key=key, Body=b"clobber", IfNoneMatch="*"))
    assert code == ("PreconditionFailed", "At least one of the pre-conditions you specified did not hold"), (
        f"expected PreconditionFailed, got {code!r}"
    )

    still = s3.get_object(Bucket=name, Key=key)
    assert still["Body"].read() == b"original", "object must be unchanged after a failed conditional write"

    # --- Restore: delete the key, then the identical call must succeed again.
    s3.delete_object(Bucket=name, Key=key)
    restored = s3.put_object(Bucket=name, Key=key, Body=b"recreated", IfNoneMatch="*")
    restored_status = restored["ResponseMetadata"]["HTTPStatusCode"]
    assert restored_status == 200, (
        f"expected the identical call to succeed again once the key was gone, got {restored_status!r}"
    )
    recreated = s3.get_object(Bucket=name, Key=key)
    assert recreated["Body"].read() == b"recreated", (
        "the restored create-if-absent PUT did not land its own bytes"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
