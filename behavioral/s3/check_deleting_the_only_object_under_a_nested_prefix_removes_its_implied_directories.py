"""deleting-the-only-object-under-a-nested-prefix-removes-its-implied-directories."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deleting-the-only-object-under-a-nested-prefix-removes-its-implied-directories"
GROUP = "subdirectory-listing"
SERVICES = ["s3"]

_NESTED_KEY = "a/b/c.txt"
_SIBLING_KEY = "z/top.txt"


def _bucket(ctx, s3, prefix: str = "sim2real-s3x-impliedir-") -> str:
    name = ctx.unique_name(prefix)
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(s3, bucket):
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        for obj in page.get("Contents", []) or []:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _prefixes(resp: dict) -> list[str]:
    return [p["Prefix"] for p in resp.get("CommonPrefixes") or []]


def _keys(resp: dict) -> list[str]:
    return [o["Key"] for o in resp.get("Contents") or []]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Deleting the only object two levels under a prefix removes every level that prefix implied:
    a Delimiter='/' listing of the bucket root no longer names the top-level prefix at all."""
    s3 = ctx.client("s3")
    bucket = _bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key=_NESTED_KEY, Body=b"nested")
    s3.put_object(Bucket=bucket, Key=_SIBLING_KEY, Body=b"sibling")

    before_root = s3.list_objects_v2(Bucket=bucket, Delimiter="/")
    assert _prefixes(before_root) == ["a/", "z/"], (
        f"before the delete, the root listing must roll up to ['a/', 'z/']; got {_prefixes(before_root)!r}"
    )
    before_a = s3.list_objects_v2(Bucket=bucket, Prefix="a/", Delimiter="/")
    assert _prefixes(before_a) == ["a/b/"], (
        f"before the delete, a/ must roll up to ['a/b/']; got {_prefixes(before_a)!r}"
    )

    s3.delete_object(Bucket=bucket, Key=_NESTED_KEY)

    after_root = s3.list_objects_v2(Bucket=bucket, Delimiter="/")
    assert _prefixes(after_root) == ["z/"], (
        f"after deleting the only object under a/b/, the root listing must drop a/ entirely "
        f"(nothing implies it any more); got {_prefixes(after_root)!r}"
    )
    assert _keys(after_root) == [], f"the root listing must still have no keys of its own; got {_keys(after_root)!r}"

    after_a = s3.list_objects_v2(Bucket=bucket, Prefix="a/", Delimiter="/")
    assert _prefixes(after_a) == [] and _keys(after_a) == [], (
        f"nothing must remain under a/ once its only object is gone; got prefixes="
        f"{_prefixes(after_a)!r}, keys={_keys(after_a)!r}"
    )

    code, message = _error(lambda: s3.get_object(Bucket=bucket, Key=_NESTED_KEY))
    assert (code, message) == ("NoSuchKey", "The specified key does not exist."), (
        f"GetObject on the deleted key returned {(code, message)!r}"
    )

    sibling_body = s3.get_object(Bucket=bucket, Key=_SIBLING_KEY)["Body"].read()
    assert sibling_body == b"sibling", f"the untouched sibling now holds {sibling_body!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
