"""s3-express-append-produces-the-exact-concatenation-of-three-offset-writes."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-express-append-produces-the-exact-concatenation-of-three-offset-writes"
GROUP = 'append-semantics'
SERVICES = ['s3']

_C1 = b"chunk-one-" * 12
_C2 = b"chunk-two-is-longer-" * 9
_C3 = b"chunk-three-" * 15
_TOTAL = len(_C1) + len(_C2) + len(_C3)
_WRITE_OFFSET_MESSAGE = (
    "The write offset value that you specified does not match the current object size."
)


def _delete_directory_bucket(client, bucket):
    """Empty then delete an S3 Express directory bucket.

    Directory buckets reject ``list_object_versions`` (NotImplemented) and hold no versions,
    so an unversioned sweep is complete.
    """
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


def _client_error(fn):
    """Call fn(); return the ClientError it raised, or None if it returned normally."""
    try:
        fn()
    except ClientError as exc:
        return exc
    return None


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """Three WriteOffsetBytes appends assemble the exact concatenation with a running Size, and
    appends at a wrong offset fail InvalidWriteOffset (400) without changing the object.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-objects-append.html
    """
    s3 = ctx.client("s3")
    ec2 = ctx.client("ec2")

    # Express is not offered in every zone (an unsupported one fails InvalidBucketName), so try
    # each available zone id and keep the first that accepts a directory bucket.
    zone_ids = [z["ZoneId"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]]
    assert zone_ids, "DescribeAvailabilityZones returned no available zones"

    bucket = None
    refusals = {}
    for zone_id in zone_ids:
        candidate = f"{ctx.unique_name('sim2real-behav-dir-')}--{zone_id}--x-s3"
        exc = _client_error(lambda name=candidate, z=zone_id: s3.create_bucket(
            Bucket=name,
            CreateBucketConfiguration={
                "Location": {"Type": "AvailabilityZone", "Name": z},
                "Bucket": {"DataRedundancy": "SingleAvailabilityZone", "Type": "Directory"},
            },
        ))
        if exc is None:
            bucket = candidate
            ctx.on_cleanup(lambda name=candidate: _delete_directory_bucket(s3, name))
            break
        refusals[zone_id] = exc.response.get("Error", {}).get("Code")
    assert bucket is not None, (
        f"no availability zone accepted an S3 Express directory bucket; the refusals were "
        f"{refusals!r} over zones {zone_ids!r}"
    )

    key = "appended.bin"

    # --- Write 1: the initial create. PutObject returns Size only on appends, so use HeadObject.
    first = s3.put_object(Bucket=bucket, Key=key, Body=_C1)
    assert first["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"the initial write returned {first['ResponseMetadata']['HTTPStatusCode']!r}"
    )
    assert s3.head_object(Bucket=bucket, Key=key)["ContentLength"] == len(_C1), (
        f"after the first write the object is "
        f"{s3.head_object(Bucket=bucket, Key=key)['ContentLength']!r} bytes, want {len(_C1)}"
    )

    # --- Writes 2 and 3: each at an offset equal to the CURRENT length.
    second = s3.put_object(Bucket=bucket, Key=key, Body=_C2, WriteOffsetBytes=len(_C1))
    assert second["Size"] == len(_C1) + len(_C2), (
        f"the second append reported Size {second.get('Size')!r}, want the running total "
        f"{len(_C1) + len(_C2)} — Size must be the object's length AFTER the append, not the "
        "length of the appended chunk"
    )
    assert s3.head_object(Bucket=bucket, Key=key)["ContentLength"] == len(_C1) + len(_C2), (
        "HeadObject does not agree with the second append's reported Size"
    )

    third = s3.put_object(Bucket=bucket, Key=key, Body=_C3,
                          WriteOffsetBytes=len(_C1) + len(_C2))
    assert third["Size"] == _TOTAL, (
        f"the third append reported Size {third.get('Size')!r}, want {_TOTAL}"
    )

    # --- The assembled object is the exact concatenation, in order.
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert body == _C1 + _C2 + _C3, (
        f"the assembled object is {len(body)} bytes starting {body[:48]!r}; want {_TOTAL} bytes "
        f"starting {(_C1 + _C2 + _C3)[:48]!r} — the offset writes were not assembled in order"
    )
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["ContentLength"] == _TOTAL, (
        f"HeadObject reports ContentLength {head['ContentLength']!r}, want {_TOTAL}"
    )
    etag_before = head["ETag"]

    # --- Three wrong offsets, each InvalidWriteOffset, each leaving the object untouched.
    for label, offset in (("the start of the object", 0),
                          ("an interior boundary", len(_C1)),
                          ("one byte past the end", _TOTAL + 1)):
        exc = _client_error(lambda o=offset: s3.put_object(
            Bucket=bucket, Key=key, Body=b"MUST-NOT-LAND", WriteOffsetBytes=o,
        ))
        assert exc is not None, (
            f"an append at {label} (WriteOffsetBytes={offset}) succeeded on a {_TOTAL}-byte "
            "object — WriteOffsetBytes is being ignored, so two concurrent appenders silently "
            "overwrite each other"
        )
        assert exc.response["Error"]["Code"] == "InvalidWriteOffset", (
            f"expected InvalidWriteOffset for an append at {label} "
            f"(WriteOffsetBytes={offset}), got {exc.response['Error']['Code']!r}"
        )
        assert exc.response["Error"].get("Message") == _WRITE_OFFSET_MESSAGE, (
            f"unexpected InvalidWriteOffset message for an append at {label}: "
            f"{exc.response['Error'].get('Message')!r}"
        )
        assert exc.response["ResponseMetadata"]["HTTPStatusCode"] == 400, (
            f"expected HTTP 400 for an append at {label}, got "
            f"{exc.response['ResponseMetadata']['HTTPStatusCode']!r}"
        )

    # --- Effect absent: none of the three refusals changed a byte.
    after = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert after == _C1 + _C2 + _C3, (
        f"a refused append modified the object: it is now {len(after)} bytes, want {_TOTAL}"
    )
    assert s3.head_object(Bucket=bucket, Key=key)["ETag"] == etag_before, (
        f"a refused append changed the object's ETag from {etag_before!r}"
    )

    # --- And a further LEGAL append still works, so the rejections did not wedge the object.
    fourth = s3.put_object(Bucket=bucket, Key=key, Body=_C1, WriteOffsetBytes=_TOTAL)
    assert fourth["Size"] == _TOTAL + len(_C1), (
        f"the append after three refusals reported Size {fourth.get('Size')!r}, want "
        f"{_TOTAL + len(_C1)}"
    )
    final = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert final == _C1 + _C2 + _C3 + _C1, (
        f"the final object is {len(final)} bytes, want {_TOTAL + len(_C1)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
