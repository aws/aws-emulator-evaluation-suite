"""conc-s3-conditional-writes-optimistic-counter-loses-no-increment."""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-s3-conditional-writes-optimistic-counter-loses-no-increment"
GROUP = 'concurrency'
SERVICES = ['s3']

_WORKERS = 4
_INCREMENTS_EACH = 5
_MAX_ATTEMPTS_PER_INCREMENT = 200
# The two documented outcomes of losing an If-Match race; a retry loop re-reads on either.
_LOST_RACE = frozenset({"PreconditionFailed", "ConditionalRequestConflict"})


def _delete_bucket(s3, bucket):
    """Abort uploads, empty every version and marker, then delete the bucket (raises if it cannot)."""
    try:
        for page in s3.get_paginator("list_multipart_uploads").paginate(Bucket=bucket):
            for u in page.get("Uploads", []):
                s3.abort_multipart_upload(Bucket=bucket, Key=u["Key"], UploadId=u["UploadId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "NoSuchUpload"):
            raise
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for o in page.get("Versions", []) + page.get("DeleteMarkers", []):
                s3.delete_object(Bucket=bucket, Key=o["Key"], VersionId=o["VersionId"])
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _new_bucket(ctx, s3):
    name = ctx.unique_name("sim2real-condw-")
    params = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; not a region pin.
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent GET-then-PutObject(If-Match) increments lose no update: the values the workers wrote
    are exactly 1..N with no duplicate, and the final object reads N with the matching ETag."""
    s3 = ctx.client("s3")
    worker_client = ctx.client(
        "s3", config=Config(max_pool_connections=_WORKERS * 2, retries={"total_max_attempts": 1})
    )
    bucket = _new_bucket(ctx, s3)
    key = "counters/jobs-processed"
    s3.put_object(Bucket=bucket, Key=key, Body=b"0")

    def _worker(w):
        wrote = []
        for _ in range(_INCREMENTS_EACH):
            for _attempt in range(_MAX_ATTEMPTS_PER_INCREMENT):
                got = worker_client.get_object(Bucket=bucket, Key=key)
                value = int(got["Body"].read())
                try:
                    worker_client.put_object(Bucket=bucket, Key=key, Body=str(value + 1).encode(),
                                             IfMatch=got["ETag"])
                except ClientError as exc:
                    if exc.response.get("Error", {}).get("Code") not in _LOST_RACE:
                        raise
                    continue
                wrote.append(value + 1)
                break
            else:
                raise AssertionError(
                    f"worker {w} could not land an increment in {_MAX_ATTEMPTS_PER_INCREMENT} "
                    "attempts; the If-Match loop never converges"
                )
        return wrote

    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        per_worker = list(pool.map(_worker, range(_WORKERS)))

    total = _WORKERS * _INCREMENTS_EACH
    written = sorted(v for vals in per_worker for v in vals)
    assert len(written) == total, (
        f"workers reported {len(written)} successful increments, want {total}: {per_worker!r}"
    )
    assert written == list(range(1, total + 1)), (
        f"successful If-Match writes produced values {written!r}; want exactly 1..{total} once "
        "each: a duplicate means two workers both won the same compare-and-swap"
    )
    for vals in per_worker:
        assert vals == sorted(vals), (
            f"one worker's own successful writes went backwards {vals!r}: a write was accepted "
            "against an ETag older than one it had already superseded"
        )

    final = s3.get_object(Bucket=bucket, Key=key)
    body = final["Body"].read()
    assert body == str(total).encode(), f"the counter reads {body!r}; want {total} (lost update)"
    want_etag = '"' + hashlib.md5(body).hexdigest() + '"'
    assert final["ETag"] == want_etag, f"final ETag {final['ETag']!r} != MD5 {want_etag!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
