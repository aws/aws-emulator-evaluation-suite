"""list-objects-v2-default-page-holds-one-thousand-keys-of-a-larger-bucket."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-objects-v2-default-page-holds-one-thousand-keys-of-a-larger-bucket"
GROUP = "pagination"
SERVICES = ["s3"]

_COUNT = 1001
_PAGE = 1000


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A bucket holds 1,001 objects; ListObjectsV2 without MaxKeys pages them 1,000 at a time.

    The first page holds the lowest 1,000 keys, truncated; its continuation token returns the last.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListObjectsV2.html
    """
    s3 = ctx.client("s3")
    bucket = _bucket(ctx)
    keys = [f"obj/{i:04d}" for i in range(_COUNT)]

    def put(key: str) -> None:
        s3.put_object(Bucket=bucket, Key=key, Body=key.encode())

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(put, keys))

    first = s3.list_objects_v2(Bucket=bucket)
    first_keys = [o["Key"] for o in first.get("Contents") or []]
    assert first["MaxKeys"] == _PAGE, (
        f"the default MaxKeys must be {_PAGE}; got {first['MaxKeys']!r}"
    )
    assert first["KeyCount"] == _PAGE, (
        f"the first page must count {_PAGE} keys; got {first['KeyCount']!r}"
    )
    assert first_keys == keys[:_PAGE], (
        f"the first page must be the {_PAGE} lowest keys in ascending order; "
        f"got {len(first_keys)} keys "
        f"from {first_keys[:1]!r} to {first_keys[-1:]!r}"
    )
    assert first["IsTruncated"] is True, (
        f"a {_COUNT}-key bucket's first page must be truncated; got {first['IsTruncated']!r}"
    )
    token = first.get("NextContinuationToken")
    assert token, "a truncated page must carry a NextContinuationToken"

    second = s3.list_objects_v2(Bucket=bucket, ContinuationToken=token)
    second_keys = [o["Key"] for o in second.get("Contents") or []]
    assert second_keys == keys[_PAGE:], (
        f"the continuation page must hold only {keys[_PAGE:]!r}; got {second_keys!r}"
    )
    assert second["KeyCount"] == _COUNT - _PAGE, (
        f"the continuation page must count {_COUNT - _PAGE} key(s); got {second['KeyCount']!r}"
    )
    assert second["IsTruncated"] is False, (
        f"the last page must not be truncated; got {second['IsTruncated']!r}"
    )
    assert second.get("ContinuationToken") == token, (
        "the continuation page must echo the token it was sent"
    )
    assert "NextContinuationToken" not in second, (
        "the last page must carry no NextContinuationToken"
    )


def _bucket(ctx) -> str:
    """An unversioned bucket whose purge-and-delete net is registered before the create."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-lpage-")
    ctx.on_cleanup(lambda: _drop_bucket(ctx, name))
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # us-east-1 is S3's default region: CreateBucket rejects an explicit LocationConstraint
        # there, so it must be omitted rather than passed.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    return name


def _drop_bucket(ctx, bucket: str) -> None:
    """The cleanup: delete every object, then the bucket; a missing bucket is fine."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents") or []]
            if objs:
                out = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
                if out.get("Errors"):
                    raise AssertionError(f"cleanup could not delete {out['Errors'][:3]!r}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
