"""delete-object-nonexistent-idempotent."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "delete-object-nonexistent-idempotent"
GROUP = 'lifecycle'
SERVICES = ['s3']

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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteObject on a key that never existed SUCCEEDS with HTTP 204 -- deletes are idempotent, not 404s."""
    from botocore.exceptions import ClientError

    def _absent(fn):
        """Call fn(); assert it fails not-found and return the error (code, message)."""
        try:
            fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError("expected the call to fail with a not-found error, but it succeeded")

    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "never-written.txt"

    resp = s3.delete_object(Bucket=bucket, Key=key)

    assert resp["ResponseMetadata"]["HTTPStatusCode"] == 204, (
        f"expected 204 for delete of a missing key, got {resp['ResponseMetadata']['HTTPStatusCode']}"
    )
    assert "DeleteMarker" not in resp, "unversioned bucket must not report a delete marker"

    # repeatable: an identical second delete of the same never-existed key is
    # itself a 204, not an error -- that is what makes this idempotent rather
    # than a one-shot side effect
    resp2 = s3.delete_object(Bucket=bucket, Key=key)
    assert resp2["ResponseMetadata"]["HTTPStatusCode"] == 204, (
        f"expected the repeat delete of a missing key to stay 204, got {resp2['ResponseMetadata']['HTTPStatusCode']}"
    )
    assert "DeleteMarker" not in resp2, "unversioned bucket must not report a delete marker on repeat delete"

    # independent read at the destination: the key is genuinely absent, not
    # merely unreported by delete_object's own response
    code, message = _absent(lambda: s3.head_object(Bucket=bucket, Key=key))
    # HEAD responses carry no body, so the code and message come from the bare 404 status.
    assert code == "404", f"expected HeadObject 404 for the absent key, got {code!r}"
    assert message == "Not Found", f"expected HeadObject's 'Not Found' for the absent key, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
