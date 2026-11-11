"""error-bucket-not-empty."""

from __future__ import annotations
from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "error-bucket-not-empty"
GROUP = 'errors'
SERVICES = ['s3']

ERR_BUCKET_NOT_EMPTY = "BucketNotEmpty"
ERR_NO_SUCH_BUCKET = "NoSuchBucket"

def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it; only an already-gone
    bucket (NoSuchBucket) is tolerated."""
    try:
        try:
            for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
                for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                    client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NotImplemented", "MethodNotAllowed"):
                raise
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for o in page.get("Contents", []):
                client.delete_object(Bucket=bucket, Key=o["Key"])
        client.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3, **kwargs):
    """Create a uniquely-named bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":  # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _err_code(fn):
    """Call fn(); return the ClientError response it raises.

    Raises on unexpected success rather than returning a falsy sentinel.
    """
    try:
        fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError("expected a ClientError, the call unexpectedly succeeded")


def _code_status(resp):
    """(Error.Code, HTTP status) of a ClientError response."""
    return resp.get("Error", {}).get("Code"), resp.get("ResponseMetadata", {}).get("HTTPStatusCode")


def _assert_gone(s3, bucket):
    """HeadBucket answers 404, ListBuckets omits it, and a PutObject into it is refused NoSuchBucket."""
    head = _err_code(lambda: s3.head_bucket(Bucket=bucket))
    code, status = _code_status(head)
    # HEAD responses carry no body, so the code and message come from the bare 404 status.
    assert code == "404" and status == 404, (
        f"expected HeadBucket 404 for the deleted bucket, got code {code!r} status {status!r}"
    )
    assert head.get("Error", {}).get("Message") == "Not Found", (
        f"expected HeadBucket's 'Not Found' for the deleted bucket, got {head.get('Error')!r}"
    )
    names = [b["Name"] for b in s3.list_buckets(Prefix=bucket).get("Buckets", [])]
    assert bucket not in names, f"deleted bucket still listed by ListBuckets: {names!r}"
    put = _err_code(lambda: s3.put_object(Bucket=bucket, Key="after-delete.txt", Body=b"x"))
    code, status = _code_status(put)
    assert code == ERR_NO_SUCH_BUCKET and isinstance(status, int) and status // 100 == 4, (
        f"expected NoSuchBucket/4xx putting into the deleted bucket, got code {code!r} status {status!r}"
    )
    assert put.get("Error", {}).get("Message") == "The specified bucket does not exist", (
        f"expected the exact NoSuchBucket message, got {put.get('Error')!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteBucket on a non-empty bucket is rejected with BucketNotEmpty; the bucket
    survives the rejected call untouched; and emptying it is exactly what flips the
    identical DeleteBucket call back to succeeding."""
    s3 = ctx.client("s3")

    # positive control: DeleteBucket itself works on this account/region before anything
    # is broken -- a separate, always-empty bucket, so the object we are about to add to
    # the bucket under test cannot be the reason a bare DeleteBucket would fail.
    control = _new_bucket(ctx, s3)
    s3.delete_bucket(Bucket=control)
    _assert_gone(s3, control)

    # break exactly one thing: the bucket under test holds an object
    bucket = _new_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="still-here.txt", Body=b"data")
    refusal = _err_code(lambda: s3.delete_bucket(Bucket=bucket))
    code, status = _code_status(refusal)
    assert code == ERR_BUCKET_NOT_EMPTY, f"expected {ERR_BUCKET_NOT_EMPTY}, got {code!r}"
    assert isinstance(status, int) and status // 100 == 4, f"expected HTTP 4xx (AWS answers 409) for {ERR_BUCKET_NOT_EMPTY}, got {status!r}"
    assert refusal.get("Error", {}).get("Message") == "The bucket you tried to delete is not empty", (
        f"expected the exact {ERR_BUCKET_NOT_EMPTY} message, got {refusal.get('Error')!r}"
    )

    # effect absent: an independent read (HeadBucket, not the failed DeleteBucket's own
    # response) still finds the bucket and its object -- the rejection removed neither
    try:
        s3.head_bucket(Bucket=bucket)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        raise AssertionError(
            f"bucket {bucket!r} is unexpectedly gone after a rejected DeleteBucket: {code!r}"
        ) from exc
    kept = s3.get_object(Bucket=bucket, Key="still-here.txt")["Body"].read()
    assert kept == b"data", f"the object changed across the rejected DeleteBucket: {kept!r}"

    # restore: removing the object is exactly what makes the identical DeleteBucket call
    # succeed afterward
    s3.delete_object(Bucket=bucket, Key="still-here.txt")
    s3.delete_bucket(Bucket=bucket)
    _assert_gone(s3, bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
