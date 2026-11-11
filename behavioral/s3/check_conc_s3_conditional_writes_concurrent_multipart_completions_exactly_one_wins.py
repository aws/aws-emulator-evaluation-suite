"""conc-s3-conditional-writes-concurrent-multipart-completions-exactly-one-wins."""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-s3-conditional-writes-concurrent-multipart-completions-exactly-one-wins"
GROUP = 'concurrency'
SERVICES = ['s3']

_RACERS = 6
_PART_BYTES = 262_144


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


def _abort_upload(s3, bucket, key, upload_id):
    try:
        s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchUpload":
            raise


def _pattern(tag, size):
    unit = hashlib.sha256(tag.encode()).digest()
    return (unit * (size // len(unit) + 1))[:size]


def _head_status(s3, bucket, key):
    """HTTP status of HeadObject on the key: 200 when it exists, the error status otherwise."""
    try:
        return s3.head_object(Bucket=bucket, Key=key)["ResponseMetadata"]["HTTPStatusCode"]
    except ClientError as exc:
        return exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Racing CompleteMultipartUpload calls for one new key with If-None-Match:* produce exactly one
    winner; every loser gets PreconditionFailed with its exact message, and the object holds the
    winner's bytes and ETag."""
    s3 = ctx.client("s3")
    racer_client = ctx.client(
        "s3", config=Config(max_pool_connections=_RACERS * 2, retries={"total_max_attempts": 1})
    )
    bucket = _new_bucket(ctx, s3)
    key = "lock/leader-election.bin"

    bodies = [_pattern(f"racer-{i}", _PART_BYTES) for i in range(_RACERS)]
    uploads = []
    for i in range(_RACERS):
        upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
        ctx.on_cleanup(lambda u=upload_id: _abort_upload(s3, bucket, key, u))
        etag = s3.upload_part(Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=1,
                              Body=bodies[i])["ETag"]
        uploads.append((upload_id, etag))

    before = _head_status(s3, bucket, key)
    assert before == 404, f"HeadObject before any completion returned {before!r}; want 404"

    def _complete(i):
        upload_id, etag = uploads[i]
        try:
            resp = racer_client.complete_multipart_upload(
                Bucket=bucket, Key=key, UploadId=upload_id,
                MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": etag}]}, IfNoneMatch="*",
            )
            return {"i": i, "ok": True, "etag": resp["ETag"]}
        except ClientError as exc:
            return {"i": i, "ok": False, "code": exc.response.get("Error", {}).get("Code"),
                    "Message": exc.response.get("Error", {}).get("Message"),
                    "status": exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")}

    with ThreadPoolExecutor(max_workers=_RACERS) as pool:
        results = list(pool.map(_complete, range(_RACERS)))

    winners = [r for r in results if r["ok"]]
    losers = [r for r in results if not r["ok"]]
    assert len(winners) == 1, (
        f"expected exactly one completion to win If-None-Match:*, got {len(winners)}: {results!r}"
    )
    assert len(losers) == _RACERS - 1, f"expected {_RACERS - 1} losers: {results!r}"
    assert all(r["code"] == "PreconditionFailed" for r in losers), (
        f"every losing completion must be PreconditionFailed, got "
        f"{[(r['code'], r['status']) for r in losers]!r}"
    )
    want = "At least one of the pre-conditions you specified did not hold"
    assert all(r["Message"] == want for r in losers), (
        f"every losing completion must say {want!r}, got {[r['Message'] for r in losers]!r}"
    )

    winner = winners[0]
    got = s3.get_object(Bucket=bucket, Key=key)
    body = got["Body"].read()
    assert body == bodies[winner["i"]], (
        f"the stored object (sha256 {hashlib.sha256(body).hexdigest()}, {len(body)} bytes) is not "
        f"racer {winner['i']}'s parts; matches racer "
        f"{[j for j, b in enumerate(bodies) if b == body]!r}"
    )
    assert got["ETag"] == winner["etag"], (
        f"GET ETag {got['ETag']!r} differs from the winning completion's {winner['etag']!r}"
    )
    assert got["ETag"].endswith('-1"'), (
        f"the object ETag {got['ETag']!r} is not a one-part multipart ETag"
    )

    listed = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        listed += [(o["Key"], o["Size"]) for o in page.get("Contents", [])]
    assert listed == [(key, _PART_BYTES)], (
        f"the bucket lists {listed!r}; want exactly one {_PART_BYTES}-byte object at {key!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
