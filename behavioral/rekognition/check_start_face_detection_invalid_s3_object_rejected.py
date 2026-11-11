"""start-face-detection-invalid-s3-object-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "start-face-detection-invalid-s3-object-rejected"
GROUP = "overly-permissive"
SERVICES = ["rekognition"]


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartFaceDetection against a real S3 object is accepted (returns a JobId); against a missing
    key it is rejected, and the identical call succeeds again once that same key is uploaded."""
    s3 = ctx.client("s3")
    rek = ctx.client("rekognition")
    bucket = ctx.unique_name("sim2real-rek-vidbucket-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    existing_key = "placeholder.mp4"
    s3.put_object(Bucket=bucket, Key=existing_key, Body=b"not a real video, just needs to exist")

    # positive control: an S3Object that exists is accepted synchronously (a job is created)
    accepted = rek.start_face_detection(Video={"S3Object": {"Bucket": bucket, "Name": existing_key}})
    assert accepted["JobId"], f"expected a JobId for an existing S3 object, got {accepted!r}"

    # negative: a key that was never uploaded is rejected before any job is created
    missing_key = "does-not-exist.mp4"
    code, message = _client_error(
        lambda: rek.start_face_detection(Video={"S3Object": {"Bucket": bucket, "Name": missing_key}})
    )
    assert code == "InvalidS3ObjectException", (
        f"expected InvalidS3ObjectException for a never-uploaded key, got {code!r}"
    )
    assert message == (
        "Unable to get object metadata from S3. Check object key, region and/or access permissions."
    ), f"expected the S3 object-metadata message for a never-uploaded key, got {message!r}"

    # restore: uploading the same key the negative call referenced flips the identical call to accepted
    s3.put_object(Bucket=bucket, Key=missing_key, Body=b"not a real video, just needs to exist")
    restored = rek.start_face_detection(Video={"S3Object": {"Bucket": bucket, "Name": missing_key}})
    assert restored["JobId"], f"expected a JobId once {missing_key!r} exists, got {restored!r}"


def _client_error(fn):
    """Call fn(); return its botocore (Error.Code, Error.Message). An unexpected SUCCESS raises,
    because a target accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objects})
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
