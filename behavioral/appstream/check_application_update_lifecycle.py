"""application-update-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "application-update-lifecycle"
GROUP = "lifecycle"
SERVICES = ["appstream"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApplication persists a new DisplayName/LaunchPath that DescribeApplications
    then reflects."""
    appstream = ctx.client("appstream")
    bucket = _create_asset_bucket(ctx)
    _put_object(ctx, bucket, "pkg/app.zip")
    _put_object(ctx, bucket, "icons/app.png")

    appblock_name = ctx.unique_name("sim2real-appstream-appblock-")
    appblock_arn = appstream.create_app_block(
        Name=appblock_name,
        PackagingType="APPSTREAM2",
        SourceS3Location={"S3Bucket": bucket, "S3Key": "pkg/app.zip"},
        Tags={"sim2real-check": "application-update-lifecycle"},
    )["AppBlock"]["Arn"]
    ctx.on_cleanup(lambda: appstream.delete_app_block(Name=appblock_name))

    app_name = ctx.unique_name("sim2real-appstream-app-")
    app_arn = appstream.create_application(
        Name=app_name,
        DisplayName="Original Display Name",
        IconS3Location={"S3Bucket": bucket, "S3Key": "icons/app.png"},
        LaunchPath="C:\\app\\original.exe",
        Platforms=["WINDOWS_SERVER_2019"],
        InstanceFamilies=["GENERAL_PURPOSE"],
        AppBlockArn=appblock_arn,
        Tags={"sim2real-check": "application-update-lifecycle"},
    )["Application"]["Arn"]
    ctx.on_cleanup(lambda: appstream.delete_application(Name=app_name))

    described = appstream.describe_applications(Arns=[app_arn])["Applications"][0]
    assert described["DisplayName"] == "Original Display Name", (
        f"expected DisplayName 'Original Display Name', got {described['DisplayName']!r}"
    )
    assert described["LaunchPath"] == "C:\\app\\original.exe", (
        f"expected LaunchPath 'C:\\\\app\\\\original.exe', got {described['LaunchPath']!r}"
    )

    appstream.update_application(
        Name=app_name,
        DisplayName="Updated Display Name",
        LaunchPath="C:\\app\\updated.exe",
    )

    described_after = appstream.describe_applications(Arns=[app_arn])["Applications"][0]
    assert described_after["DisplayName"] == "Updated Display Name", (
        f"expected DisplayName 'Updated Display Name' after UpdateApplication, "
        f"got {described_after['DisplayName']!r}"
    )
    assert described_after["LaunchPath"] == "C:\\app\\updated.exe", (
        f"expected LaunchPath 'C:\\\\app\\\\updated.exe' after UpdateApplication, "
        f"got {described_after['LaunchPath']!r}"
    )


def _create_asset_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-appstream-assets-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
    )
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real-check", "Value": "application-update-lifecycle"}]},
    )
    import json

    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowAppStream2Access",
                        "Effect": "Allow",
                        "Principal": {"Service": "appstream.amazonaws.com"},
                        "Action": [
                            "s3:GetObject",
                            "s3:ListBucket",
                            "s3:PutObject",
                            "s3:GetBucketOwnershipControls",
                        ],
                        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    }
                ],
            }
        ),
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _put_object(ctx, bucket: str, key: str) -> None:
    ctx.client("s3").put_object(
        Bucket=bucket, Key=key, Body=b"sim2real-appstream-asset", ACL="bucket-owner-full-control"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

