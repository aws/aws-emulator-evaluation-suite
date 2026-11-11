"""multipart-upload-part-invalid-number-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "multipart-upload-part-invalid-number-rejected"
GROUP = 'multipart'
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
    """Create a uniquely-named, tagged bucket, register empty+delete teardown, return its name."""
    name = kwargs.pop("Bucket", None) or ctx.unique_name("sim2real-behav-bkt-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    params.update(kwargs)
    s3.create_bucket(**params)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _err_code(fn):
    """Call fn(); return botocore (Code, Message) if a ClientError is raised. An unexpected SUCCESS
    raises, because a target ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """UploadPart with PartNumber outside 1..10000 must be rejected with InvalidArgument, while a
    valid PartNumber on the same upload still succeeds."""
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)
    key = "mpu-badpartnum.bin"
    upload_id = s3.create_multipart_upload(Bucket=bucket, Key=key)["UploadId"]

    # Positive control: a valid PartNumber must succeed on this same upload, so the negatives
    # below prove a specific rejection rather than a target that refuses UploadPart outright.
    good = s3.upload_part(Bucket=bucket, Key=key, PartNumber=1, UploadId=upload_id, Body=b"good")
    assert good.get("ETag"), f"valid PartNumber=1 must succeed with an ETag, got {good!r}"

    for bad_part_number in (0, 10001):
        code, message = _err_code(lambda pn=bad_part_number: s3.upload_part(
            Bucket=bucket, Key=key, PartNumber=pn, UploadId=upload_id, Body=b"x",
        ))
        assert code == "InvalidArgument", (
            f"expected InvalidArgument for PartNumber={bad_part_number}, got {code!r}"
        )
        assert message == "Part number must be an integer between 1 and 10000, inclusive", message

    parts = s3.list_parts(Bucket=bucket, Key=key, UploadId=upload_id).get("Parts", [])
    part_numbers = sorted(p["PartNumber"] for p in parts)
    assert part_numbers == [1], (
        f"only the valid PartNumber=1 part must be recorded, rejected parts must leave no trace, "
        f"got {part_numbers}"
    )

    # Cleanup
    s3.abort_multipart_upload(Bucket=bucket, Key=key, UploadId=upload_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
