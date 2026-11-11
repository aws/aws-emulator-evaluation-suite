"""appblock-deletion-blocked-while-associated-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "appblock-deletion-blocked-while-associated-rejected"
GROUP = "overly-permissive"
SERVICES = ["appstream"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAppBlock while an Application still references it is rejected with
    ResourceInUseException; the app block survives, and deleting it after removing the
    referencing application (the positive control) succeeds."""
    appstream = ctx.client("appstream")
    bucket = _create_asset_bucket(ctx)
    _put_object(ctx, bucket, "pkg/app.zip")
    _put_object(ctx, bucket, "icons/app.png")

    appblock_name = ctx.unique_name("sim2real-appstream-appblock-")
    appblock_arn = appstream.create_app_block(
        Name=appblock_name,
        PackagingType="APPSTREAM2",
        SourceS3Location={"S3Bucket": bucket, "S3Key": "pkg/app.zip"},
        Tags={"sim2real": CHECK},
    )["AppBlock"]["Arn"]
    appblock_deleted = False

    def _cleanup_appblock():
        if not appblock_deleted:
            appstream.delete_app_block(Name=appblock_name)

    ctx.on_cleanup(_cleanup_appblock)

    app_name = ctx.unique_name("sim2real-appstream-app-")
    appstream.create_application(
        Name=app_name,
        IconS3Location={"S3Bucket": bucket, "S3Key": "icons/app.png"},
        LaunchPath="C:\\app\\app.exe",
        Platforms=["WINDOWS_SERVER_2019"],
        InstanceFamilies=["GENERAL_PURPOSE"],
        AppBlockArn=appblock_arn,
        Tags={"sim2real": CHECK},
    )
    app_deleted = False

    def _cleanup_app():
        if not app_deleted:
            appstream.delete_application(Name=app_name)

    ctx.on_cleanup(_cleanup_app)

    code, message = _error(lambda: appstream.delete_app_block(Name=appblock_name))
    assert code == "ResourceInUseException", (
        f"expected ResourceInUseException deleting an app block still referenced by "
        f"application {app_name!r}, got {code!r}"
    )
    expected_message = f"The app-block {appblock_name} is currently in use."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the app block still exists
    described = appstream.describe_app_blocks(Arns=[appblock_arn])["AppBlocks"]
    assert len(described) == 1, (
        f"expected the blocked delete to leave the app block in place, "
        f"DescribeAppBlocks returned {len(described)} entries: {described!r}"
    )

    # positive control: after removing the referencing application, delete succeeds
    appstream.delete_application(Name=app_name)
    app_deleted = True
    appstream.delete_app_block(Name=appblock_name)
    appblock_deleted = True

    code, message = _error(lambda: appstream.describe_app_blocks(Arns=[appblock_arn]))
    assert code == "ResourceNotFoundException", (
        f"expected DescribeAppBlocks to report ResourceNotFoundException once the "
        f"referencing application is gone and the app block is deleted, got {code!r}"
    )
    expected_message = f"The App block {appblock_arn} for account {ctx.account} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # gone means unusable, not just unlisted: a second delete on the dead id also fails
    code, message = _error(lambda: appstream.delete_app_block(Name=appblock_name))
    assert code == "ResourceNotFoundException", (
        f"expected a repeat DeleteAppBlock on an already-deleted app block to report "
        f"ResourceNotFoundException, not success or a different error, got {code!r}"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _create_asset_bucket(ctx) -> str:
    """Create a real S3 bucket with objects so AppStream's S3Bucket/S3Key existence
    checks (CreateAppBlock/CreateApplication/CreateThemeForStack) pass on real AWS."""
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-appstream-assets-").lower().replace("_", "-")
    region = ctx.region
    # us-east-1 is a hardcoded literal here because S3's CreateBucket signature itself special-cases
    # it (a LocationConstraint is rejected there), not because this resource is region-pinned.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_ownership_controls(
        Bucket=bucket, OwnershipControls={"Rules": [{"ObjectOwnership": "BucketOwnerPreferred"}]}
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


def _error(fn):
    """Call fn(); return the (code, message) of the botocore error it raises. An unexpected SUCCESS
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
