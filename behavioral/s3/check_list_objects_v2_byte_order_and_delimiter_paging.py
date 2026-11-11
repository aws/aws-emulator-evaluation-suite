"""list-objects-v2-byte-order-and-delimiter-paging."""

from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-objects-v2-byte-order-and-delimiter-paging"
GROUP = 'pagination'
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
    """ListObjectsV2 returns keys in ascending UTF-8 byte order, including across pages.

    MaxKeys bounds Contents plus CommonPrefixes together, and a continuation token resumes the stream.
    """
    s3 = ctx.client("s3")

    # ---------- Part 1: the server's ordering is ascending UTF-8 byte order. ----------
    order_bucket = _new_bucket(ctx, s3)
    # Chosen to separate byte order from the two orderings emulators substitute for it:
    # case-insensitive ('A','a','Z','z') and locale collation (which files 'é' next to 'e').
    unordered = ["z.txt", "é.txt", "A.txt", "_.txt", "0.txt", "a.txt", "Z.txt"]
    for k in unordered:
        s3.put_object(Bucket=order_bucket, Key=k, Body=b"x")

    expected_order = ["0.txt", "A.txt", "Z.txt", "_.txt", "a.txt", "z.txt", "é.txt"]
    # Self-check: the literal above really is UTF-8 byte order, so a failure below is the
    # emulator's, not this check's.
    assert expected_order == sorted(expected_order, key=lambda k: k.encode("utf-8")), (
        "the expected_order literal is not UTF-8-byte-sorted"
    )
    assert set(expected_order) == set(unordered), (
        f"expected_order and unordered must contain the same keys; got {set(expected_order)!r} vs "
        f"{set(unordered)!r}"
    )

    resp = s3.list_objects_v2(Bucket=order_bucket)
    got = [o["Key"] for o in resp.get("Contents", [])]
    assert got == expected_order, (
        f"ListObjectsV2 must return keys in ascending UTF-8 byte order {expected_order}, got {got} "
        "(insertion order, case-insensitive order, or locale collation all fail here)"
    )
    assert resp.get("IsTruncated") is False, "a 7-key listing under the default MaxKeys is not truncated"
    assert resp.get("KeyCount") == 7, f"expected KeyCount=7, got {resp.get('KeyCount')!r}"

    # Ordering must survive paging: one key per page, in the same order, with no repeats.
    paged = [
        o["Key"]
        for page in s3.get_paginator("list_objects_v2").paginate(
            Bucket=order_bucket, PaginationConfig={"PageSize": 1}
        )
        for o in page.get("Contents", [])
    ]
    assert paged == expected_order, (
        f"paging one key at a time must reproduce the same byte order exactly once each; expected "
        f"{expected_order}, got {paged}"
    )

    # ---------- Part 2: MaxKeys is a budget over Contents AND CommonPrefixes. ----------
    tree_bucket = _new_bucket(ctx, s3)
    for k in ["root-a.txt", "root-z.txt", "x/1.txt", "x/2.txt", "y/1.txt", "y/2.txt"]:
        s3.put_object(Bucket=tree_bucket, Key=k, Body=b"x")

    # Ungrouped baseline: 2 root objects + 2 rolled-up prefixes, merged in byte order
    # ('r' < 'x' < 'y'), so the logical stream is root-a.txt, root-z.txt, x/, y/.
    full = s3.list_objects_v2(Bucket=tree_bucket, Delimiter="/")
    assert [o["Key"] for o in full.get("Contents", [])] == ["root-a.txt", "root-z.txt"], (
        f"expected the two root keys, got {[o['Key'] for o in full.get('Contents', [])]}"
    )
    assert [p["Prefix"] for p in full.get("CommonPrefixes", [])] == ["x/", "y/"], (
        f"expected CommonPrefixes ['x/', 'y/'] in byte order, got "
        f"{[p['Prefix'] for p in full.get('CommonPrefixes', [])]}"
    )
    assert full.get("KeyCount") == 4, (
        f"KeyCount must count CommonPrefixes as well as Contents (2 + 2 = 4), got "
        f"{full.get('KeyCount')!r}"
    )
    assert full.get("IsTruncated") is False, (
        f"an ungrouped 4-entry listing under the default MaxKeys must not be truncated, got "
        f"{full.get('IsTruncated')!r}"
    )

    # MaxKeys=3 must cut the merged stream after root-a.txt, root-z.txt, x/ — leaving y/ for the
    # next page. An emulator that applies MaxKeys to Contents only returns all of x/ and y/ here.
    page1 = s3.list_objects_v2(Bucket=tree_bucket, Delimiter="/", MaxKeys=3)
    assert [o["Key"] for o in page1.get("Contents", [])] == ["root-a.txt", "root-z.txt"], (
        f"page 1 Contents wrong: {[o['Key'] for o in page1.get('Contents', [])]}"
    )
    assert [p["Prefix"] for p in page1.get("CommonPrefixes", [])] == ["x/"], (
        "with MaxKeys=3 the budget is spent after 2 keys + 1 common prefix, so only 'x/' fits; got "
        f"{[p['Prefix'] for p in page1.get('CommonPrefixes', [])]}"
    )
    assert page1.get("KeyCount") == 3, f"expected KeyCount=3, got {page1.get('KeyCount')!r}"
    assert page1.get("IsTruncated") is True, "MaxKeys=3 over a 4-entry stream must be truncated"
    token = page1.get("NextContinuationToken")
    assert token, "a truncated page must supply NextContinuationToken"

    # Resuming must yield exactly the remainder — the tail of the merged stream, not a restart.
    page2 = s3.list_objects_v2(
        Bucket=tree_bucket, Delimiter="/", MaxKeys=3, ContinuationToken=token
    )
    assert page2.get("Contents", []) == [], (
        f"page 2 must contain no objects, got {[o['Key'] for o in page2.get('Contents', [])]}"
    )
    assert [p["Prefix"] for p in page2.get("CommonPrefixes", [])] == ["y/"], (
        f"resuming must return only the remaining prefix 'y/', got "
        f"{[p['Prefix'] for p in page2.get('CommonPrefixes', [])]}"
    )
    assert page2.get("IsTruncated") is False, "the second page exhausts the stream"
    assert page2.get("ContinuationToken") == token, (
        "the response must echo the ContinuationToken it was given, got "
        f"{page2.get('ContinuationToken')!r}"
    )

    # Whole-stream integrity across the smallest possible pages: every entry appears exactly once,
    # in byte order, with prefixes and objects interleaved correctly.
    merged = []
    next_token = None
    for _ in range(10):
        kwargs = {"Bucket": tree_bucket, "Delimiter": "/", "MaxKeys": 1}
        if next_token:
            kwargs["ContinuationToken"] = next_token
        page = s3.list_objects_v2(**kwargs)
        merged += [o["Key"] for o in page.get("Contents", [])]
        merged += [p["Prefix"] for p in page.get("CommonPrefixes", [])]
        if not page.get("IsTruncated"):
            break
        next_token = page["NextContinuationToken"]
        assert next_token, "a truncated MaxKeys=1 page must supply NextContinuationToken"
    assert merged == ["root-a.txt", "root-z.txt", "x/", "y/"], (
        "paging one entry at a time must reproduce the merged byte-ordered stream exactly once "
        f"each; got {merged}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
