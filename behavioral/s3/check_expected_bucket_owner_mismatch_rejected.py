"""expected-bucket-owner-mismatch-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "expected-bucket-owner-mismatch-rejected"
GROUP = 'auth_enforcement'
SERVICES = ['s3']

_MISMATCH_MESSAGE = "Access Denied"


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


def _other_account(account: str) -> str:
    """The documentation account id 111122223333, a well-formed id that is not `account`."""
    assert len(account) == 12 and account.isdigit(), f"unexpected account id shape: {account!r}"
    return "111122223333"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """x-amz-expected-bucket-owner is enforced: a mismatched owner is AccessDenied even for the real owner.

    The header is a precondition independent of the IAM decision, so it is asserted on both a
    bucket-scoped and an object-scoped operation.
    """
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    wrong = _other_account(account)
    bucket = _new_bucket(ctx, s3)
    key = "owned.txt"
    body = b"owner-guarded"
    s3.put_object(Bucket=bucket, Key=key, Body=body)

    # --- Control: the TRUE owner id is accepted on both a bucket op and an object op.
    resp = s3.list_objects_v2(Bucket=bucket, ExpectedBucketOwner=account)
    assert [o["Key"] for o in resp.get("Contents", [])] == [key], (
        f"ListObjectsV2 with the correct ExpectedBucketOwner must succeed, got {resp.get('Contents')!r}"
    )
    got = s3.get_object(Bucket=bucket, Key=key, ExpectedBucketOwner=account)["Body"].read()
    assert got == body, f"GetObject with the correct ExpectedBucketOwner must return {body!r}, got {got!r}"

    # --- Break exactly one thing: the same calls with a wrong (but well-formed) owner id.
    exc = _client_error(lambda: s3.list_objects_v2(Bucket=bucket, ExpectedBucketOwner=wrong))
    assert exc is not None, (
        f"ListObjectsV2 with ExpectedBucketOwner={wrong} (the bucket is owned by {account}) "
        "succeeded; the confused-deputy guard is not enforced on bucket ops"
    )
    code = exc.response.get("Error", {}).get("Code")
    status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert code == "AccessDenied", (
        f"expected AccessDenied for a mismatched ExpectedBucketOwner, got {code!r}"
    )
    assert status == 403, f"expected HTTP 403 for a mismatched ExpectedBucketOwner, got {status!r}"
    assert exc.response.get("Error", {}).get("Message") == _MISMATCH_MESSAGE, exc.response.get("Error")

    exc = _client_error(
        lambda: s3.get_object(Bucket=bucket, Key=key, ExpectedBucketOwner=wrong)
    )
    assert exc is not None, (
        "GetObject with a mismatched ExpectedBucketOwner succeeded; the guard is not enforced on "
        "object ops"
    )
    assert exc.response.get("Error", {}).get("Code") == "AccessDenied", (
        f"expected AccessDenied on the object path too, got {exc.response.get('Error', {}).get('Code')!r}"
    )
    assert exc.response.get("Error", {}).get("Message") == _MISMATCH_MESSAGE, exc.response.get("Error")

    # --- The guard also blocks WRITES, not just reads: the mismatch must not mutate anything.
    exc = _client_error(
        lambda: s3.put_object(
            Bucket=bucket, Key="written-by-wrong-owner.txt", Body=b"x", ExpectedBucketOwner=wrong
        )
    )
    assert exc is not None, "PutObject with a mismatched ExpectedBucketOwner succeeded"
    assert exc.response.get("Error", {}).get("Code") == "AccessDenied", (
        f"expected AccessDenied for a guarded write, got {exc.response.get('Error', {}).get('Code')!r}"
    )
    assert exc.response.get("Error", {}).get("Message") == _MISMATCH_MESSAGE, exc.response.get("Error")

    exc = _client_error(
        lambda: s3.delete_object(Bucket=bucket, Key=key, ExpectedBucketOwner=wrong)
    )
    assert exc is not None, (
        "DeleteObject with a mismatched ExpectedBucketOwner succeeded; a guarded delete that runs "
        "anyway is unrecoverable"
    )
    assert exc.response.get("Error", {}).get("Code") == "AccessDenied", (
        f"expected AccessDenied for a guarded delete, got {exc.response.get('Error', {}).get('Code')!r}"
    )
    assert exc.response.get("Error", {}).get("Message") == _MISMATCH_MESSAGE, exc.response.get("Error")

    # --- Effect absent: no write landed and no delete happened.
    listed = {
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket)
        for o in page.get("Contents", [])
    }
    assert listed == {key}, (
        f"the guarded write/delete changed the bucket; expected exactly {{{key!r}}}, got {sorted(listed)}"
    )
    assert s3.get_object(Bucket=bucket, Key=key)["Body"].read() == body, "the guarded object's body changed"

    # --- Control still works: omitting the header, and passing the true owner, both still succeed.
    got = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert got == body, f"GetObject with no ExpectedBucketOwner header must return {body!r}, got {got!r}"
    length = s3.head_object(Bucket=bucket, Key=key, ExpectedBucketOwner=account)["ContentLength"]
    assert length == len(body), (
        f"HeadObject with the correct ExpectedBucketOwner must report ContentLength {len(body)}, got {length}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
