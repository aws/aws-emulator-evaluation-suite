"""create-fpga-image-invalid-bucket-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-fpga-image-invalid-bucket-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFpgaImage refuses a malformed bucket name with InaccessibleStorageLocation and a location without Key
    with InvalidParameterValue, each with its exact message, while a real bucket and key are accepted and the
    image is visible through DescribeFpgaImages.
    """
    ec2 = ctx.client("ec2")
    s3 = ctx.client("s3")

    # Negative: a malformed S3 bucket name is rejected with the specific,
    # deterministic error code, not merely "some" error.
    bad_bucket, bad_key = "Invalid_Bucket_Name!", "dcp/example.tar"
    bucket_code, bucket_message = _client_error(
        lambda: ec2.create_fpga_image(InputStorageLocation={"Bucket": bad_bucket, "Key": bad_key})
    )
    assert bucket_code == "InaccessibleStorageLocation", (
        "expected CreateFpgaImage to reject a malformed S3 bucket name with "
        f"InaccessibleStorageLocation, got {bucket_code!r}"
    )
    expected_bucket_message = (
        "Error accessing resource in S3. Check permissions, naming, and ensure the bucket is "
        f"within the same region as the API endpoint. Bucket: {bad_bucket}, Key: {bad_key}."
    )
    assert bucket_message == expected_bucket_message, (
        f"expected message {expected_bucket_message!r}, got {bucket_message!r}"
    )

    # A distinct boundary: an InputStorageLocation missing the required Key
    # field is rejected with a DIFFERENT, specific error code -- proving this
    # is a separate validation path from the bucket-accessibility check above.
    key_code, key_message = _client_error(
        lambda: ec2.create_fpga_image(
            InputStorageLocation={"Bucket": ctx.unique_name("sim2real-behav-fpga-")}
        )
    )
    assert key_code == "InvalidParameterValue", (
        "expected CreateFpgaImage to reject an InputStorageLocation missing Key with "
        f"InvalidParameterValue, got {key_code!r}"
    )
    expected_key_message = (
        "InputStorageLocation is mandatory. Its bucket and key cannot be null or of length zero."
    )
    assert key_message == expected_key_message, (
        f"expected message {expected_key_message!r}, got {key_message!r}"
    )
    assert key_code != bucket_code, (
        "expected the missing-Key rejection to be a DIFFERENT error than the "
        f"malformed-bucket rejection, got the same code {key_code!r} for both"
    )

    # Positive control: a real bucket and key are accepted, so the refusals above are about the
    # storage location, not every CreateFpgaImage call.
    real_bucket = ctx.unique_name("sim2real-behav-fpga-real-")
    region = ctx.region
    if region == "us-east-1":
        # S3 quirk, not a region pin: CreateBucket rejects an explicit
        # LocationConstraint for us-east-1 (its own default region).
        s3.create_bucket(Bucket=real_bucket)
    else:
        s3.create_bucket(Bucket=real_bucket, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, real_bucket))
    s3.put_bucket_tagging(Bucket=real_bucket, Tagging={"TagSet": [{"Key": "sim2real-behav", "Value": CHECK}]})
    s3.put_object(Bucket=real_bucket, Key="dcp/example.tar", Body=b"not-a-real-dcp-tarball")

    resp = ec2.create_fpga_image(
        InputStorageLocation={"Bucket": real_bucket, "Key": "dcp/example.tar"},
        TagSpecifications=[
            {"ResourceType": "fpga-image", "Tags": [{"Key": "sim2real-behav", "Value": CHECK}]}
        ],
    )
    real_image_id = resp["FpgaImageId"]
    ctx.on_cleanup(lambda: _delete_fpga_image(ec2, real_image_id))

    # Terminal read: an independent operation, at the destination, confirms
    # the accepted create actually landed server-side.
    described = ec2.describe_fpga_images(FpgaImageIds=[real_image_id]).get("FpgaImages", [])
    assert described and described[0]["FpgaImageId"] == real_image_id, (
        "expected the accepted CreateFpgaImage against a real, accessible bucket to be "
        f"visible via DescribeFpgaImages, got {described!r}"
    )


def _client_error(fn):
    """Call *fn*; return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _delete_fpga_image(ec2, fpga_image_id):
    try:
        ec2.delete_fpga_image(FpgaImageId=fpga_image_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidFpgaImageID.NotFound":
            raise


def _delete_bucket(s3, bucket):
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
