"""list-objects-v2-is-exact-on-the-first-read-after-a-bulk-delete."""

from __future__ import annotations

import concurrent.futures

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-objects-v2-is-exact-on-the-first-read-after-a-bulk-delete"
GROUP = "consistency"
SERVICES = ["s3"]

_PREFIX = "batch/"
_TOTAL = 120
_PAGE = 25
_THREADS = 12


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The first paginated ListObjectsV2 after bulk writes and a bulk delete is exact, with no retry.

    Keys stay in UTF-8 byte order across pages, tokens replay, and repeated listings are identical.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/Welcome.html#ConsistencyModel
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    written = [f"{_PREFIX}{i:04d}.txt" for i in range(_TOTAL)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=_THREADS) as pool:
        for _ in pool.map(
            lambda key: s3.put_object(Bucket=bucket, Key=key, Body=key.encode()), written
        ):
            pass

    # No retry: S3 LIST is strongly consistent, and a poll would hide an asynchronous listing index.
    listed, pages = _list_all(s3, bucket)
    assert listed == written, (
        f"the first paginated listing after {_TOTAL} writes returned {len(listed)} keys; expected "
        f"{_TOTAL}. Missing {sorted(set(written) - set(listed))[:5]}, unexpected "
        f"{sorted(set(listed) - set(written))[:5]}"
    )
    assert listed == sorted(listed), (
        f"ListObjectsV2 did not return keys in ascending UTF-8 byte order; the first disorder is at "
        f"index {_first_disorder(listed)}"
    )
    expected_pages = -(-_TOTAL // _PAGE)
    assert len(pages) == expected_pages, (
        f"MaxKeys={_PAGE} over {_TOTAL} keys produced {len(pages)} pages, expected {expected_pages}"
    )
    for index, page in enumerate(pages):
        keys = [o["Key"] for o in page.get("Contents", [])]
        assert page["KeyCount"] == len(keys), (
            f"page {index} reports KeyCount {page['KeyCount']} but carries {len(keys)} keys"
        )
        last = index == len(pages) - 1
        assert page["IsTruncated"] is (not last), (
            f"page {index} of {len(pages)} reports IsTruncated {page['IsTruncated']!r}; only the "
            "last page may be untruncated"
        )
        assert ("NextContinuationToken" in page) is (not last), (
            f"page {index} of {len(pages)} carries NextContinuationToken "
            f"{page.get('NextContinuationToken')!r}; a token must be present exactly when the page "
            "is truncated"
        )

    # --- A saved token reproduces its page exactly.
    token = pages[0]["NextContinuationToken"]
    replayed = s3.list_objects_v2(
        Bucket=bucket, Prefix=_PREFIX, MaxKeys=_PAGE, ContinuationToken=token
    )
    assert [o["Key"] for o in replayed.get("Contents", [])] == [
        o["Key"] for o in pages[1].get("Contents", [])
    ], (
        "re-issuing the continuation token from page 0 returned a different page 1 than the "
        "original pagination did"
    )

    # --- Bulk delete every even-numbered key, then read ONCE.
    doomed = [k for i, k in enumerate(written) if i % 2 == 0]
    survivors = [k for i, k in enumerate(written) if i % 2 == 1]
    deleted = s3.delete_objects(
        Bucket=bucket, Delete={"Objects": [{"Key": k} for k in doomed], "Quiet": False}
    )
    assert sorted(d["Key"] for d in deleted.get("Deleted", [])) == sorted(doomed), (
        f"DeleteObjects reported {len(deleted.get('Deleted', []))} deletions and "
        f"{len(deleted.get('Errors', []))} errors ({deleted.get('Errors', [])[:3]}); expected "
        f"{len(doomed)} deletions and no errors"
    )

    after, _ = _list_all(s3, bucket)
    assert after == survivors, (
        f"the FIRST paginated listing after deleting {len(doomed)} keys returned {len(after)} keys; "
        f"expected exactly the {len(survivors)} survivors. Still listed but deleted: "
        f"{sorted(set(after) & set(doomed))[:5]}; missing survivors: "
        f"{sorted(set(survivors) - set(after))[:5]} — the listing index is not strongly consistent "
        "with the delete"
    )
    assert after == sorted(after), (
        "the post-delete listing is not in ascending UTF-8 byte order at index "
        f"{_first_disorder(after)}"
    )

    # --- Freeze detector: reading does not advance state.
    repeats = [_list_all(s3, bucket)[0] for _ in range(3)]
    assert repeats[0] == repeats[1] == repeats[2] == survivors, (
        "three consecutive full paginations disagreed: lengths "
        f"{[len(r) for r in repeats]} — a listing must not be consumed by being read"
    )

    # --- Terminal reads through a different operation, at the destination.
    assert s3.head_object(Bucket=bucket, Key=survivors[0])["ContentLength"] == len(
        survivors[0].encode()
    ), f"HeadObject on the surviving key {survivors[0]!r} reports the wrong size"
    assert _error_code(lambda: s3.head_object(Bucket=bucket, Key=doomed[0])) == "404", (
        f"HeadObject still finds the deleted key {doomed[0]!r}"
    )


def _delete_bucket(client, bucket):
    """Empty a bucket (objects + versions + delete markers) then delete it. TEARDOWN ONLY —
    never on an assertion path."""
    try:
        for page in client.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                client.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in client.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if keys:
                failed = client.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        client.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    """Create a uniquely-named, tagged bucket; register empty+delete teardown; return its name."""
    name = ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"},
                            {"Key": "sim2real:check", "Value": CHECK}]},
    )
    return name


def _list_all(s3, bucket):
    """Page through ListObjectsV2 with MaxKeys=_PAGE. Returns (keys, raw pages).

    Deliberately NOT a poll: the caller asserts the FIRST result. The page budget is a hard bound
    so a target that never stops truncating fails loudly instead of looping."""
    keys: list[str] = []
    pages: list[dict] = []
    token = None
    budget = 4 * (-(-_TOTAL // _PAGE)) + 4
    while True:
        kwargs = {"Bucket": bucket, "Prefix": _PREFIX, "MaxKeys": _PAGE}
        if token is not None:
            kwargs["ContinuationToken"] = token
        page = s3.list_objects_v2(**kwargs)
        pages.append(page)
        keys.extend(o["Key"] for o in page.get("Contents", []))
        assert len(pages) <= budget, (
            f"ListObjectsV2 produced more than {budget} pages of at most {_PAGE} keys for a bucket "
            f"holding at most {_TOTAL} keys; it is not terminating"
        )
        if not page.get("IsTruncated"):
            return keys, pages
        token = page["NextContinuationToken"]


def _first_disorder(keys) -> int:
    """The index of the first key that is smaller than its predecessor, or -1."""
    for i in range(1, len(keys)):
        if keys[i] < keys[i - 1]:
            return i
    return -1


def _error_code(fn) -> str:
    """The botocore Error.Code (or HTTP status for a code-less HEAD) of fn(); RAISES if fn succeeds."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code and not code.isdigit():
            return code
        return str(exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode", "unknown"))
    raise AssertionError("the call was expected to fail and it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
