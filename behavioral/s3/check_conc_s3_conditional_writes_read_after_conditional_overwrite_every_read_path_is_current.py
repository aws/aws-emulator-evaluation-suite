"""conc-s3-conditional-writes-read-after-conditional-overwrite-every-read-path-is-current."""

from __future__ import annotations

import hashlib

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "conc-s3-conditional-writes-read-after-conditional-overwrite-every-read-path-is-current"
GROUP = 'consistency'
SERVICES = ['s3']

_ROUNDS = 8
_MIB = 1024 * 1024


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


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After each of eight If-Match overwrites (the last via multipart), GET, HEAD, ListObjectsV2
    and GetObjectAttributes immediately agree on the new bytes, ETag and size (strong consistency).
    """
    s3 = ctx.client("s3")
    cas = ctx.client("s3", config=Config(retries={"total_max_attempts": 1}))
    bucket = _new_bucket(ctx, s3)
    key = "state/document.json"

    etag = s3.put_object(Bucket=bucket, Key=key, Body=b"{}")["ETag"]
    for r in range(1, _ROUNDS + 1):
        size = r * 9_973 + (r % 3) * 511
        body = _pattern(f"round-{r}", size)
        if r < _ROUNDS:
            new_etag = cas.put_object(Bucket=bucket, Key=key, Body=body, IfMatch=etag)["ETag"]
        else:
            size = 5 * _MIB + 4_321
            body = _pattern("round-final-multipart", size)
            upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]
            ctx.on_cleanup(lambda u=upload_id: _abort_upload(s3, bucket, key, u))
            parts = []
            for n, chunk in enumerate((body[:5 * _MIB], body[5 * _MIB:]), start=1):
                parts.append({"PartNumber": n, "ETag": s3.upload_part(
                    Bucket=bucket, Key=key, UploadId=upload_id, PartNumber=n, Body=chunk)["ETag"]})
            new_etag = cas.complete_multipart_upload(
                Bucket=bucket, Key=key, UploadId=upload_id,
                MultipartUpload={"Parts": parts}, IfMatch=etag)["ETag"]
        assert new_etag != etag, f"round {r}: overwrite kept ETag {etag!r}"

        got = s3.get_object(Bucket=bucket, Key=key)
        read = got["Body"].read()
        assert read == body, (
            f"round {r}: immediate GET returned {len(read)} bytes (sha256 "
            f"{hashlib.sha256(read).hexdigest()}), not the {size}-byte body just written"
        )
        assert got["ETag"] == new_etag, f"round {r}: GET ETag {got['ETag']!r} != {new_etag!r}"

        head = s3.head_object(Bucket=bucket, Key=key)
        assert (head["ETag"], head["ContentLength"]) == (new_etag, size), (
            f"round {r}: HEAD reports {(head['ETag'], head['ContentLength'])!r}; want "
            f"{(new_etag, size)!r}"
        )

        listed = []
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            listed += [(o["Key"], o["ETag"], o["Size"]) for o in page.get("Contents", [])]
        assert listed == [(key, new_etag, size)], (
            f"round {r}: ListObjectsV2 reports {listed!r}; want [{(key, new_etag, size)!r}]"
        )

        attrs = s3.get_object_attributes(Bucket=bucket, Key=key,
                                         ObjectAttributes=["ETag", "ObjectSize"])
        assert (attrs["ETag"], attrs["ObjectSize"]) == (new_etag.strip('"'), size), (
            f"round {r}: GetObjectAttributes reports {(attrs['ETag'], attrs['ObjectSize'])!r}; "
            f"want {(new_etag.strip(chr(34)), size)!r}"
        )
        # The next If-Match uses the ETag just read, so a stale read would 412 the next round.
        etag = got["ETag"]

    assert etag.endswith('-2"'), f"the final multipart overwrite has ETag {etag!r}; want a -2 ETag"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
