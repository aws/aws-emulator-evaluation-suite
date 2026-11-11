"""create-application-nonexistent-appblock-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-application-nonexistent-appblock-rejected"
GROUP = "overly-permissive"
SERVICES = ["appstream"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApplication with an AppBlockArn that does not reference an existing app block is
    rejected with ResourceNotFoundException; no Application is created, and creating the same
    application with a valid AppBlockArn (the positive control) succeeds."""
    appstream = ctx.client("appstream")
    bucket = _create_asset_bucket(ctx)
    _put_object(ctx, bucket, "icons/app.png")

    app_name = ctx.unique_name("sim2real-appstream-app-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    fake_appblock_arn = (
        f"arn:aws:appstream:{ctx.region}:{account_id}:app-block/"
        f"{ctx.unique_name('sim2real-does-not-exist-appblock-')}"
    )

    code, message = _error(
        lambda: appstream.create_application(
            Name=app_name,
            IconS3Location={"S3Bucket": bucket, "S3Key": "icons/app.png"},
            LaunchPath="C:\\app\\app.exe",
            Platforms=["WINDOWS_SERVER_2019"],
            InstanceFamilies=["GENERAL_PURPOSE"],
            AppBlockArn=fake_appblock_arn,
            Tags={"sim2real:managed": "true"},
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent AppBlockArn, got {code!r}"
    )
    expected_message = f"The App block {fake_appblock_arn} for account {ctx.account} does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the application was never created
    found = _find_application_by_name(appstream, app_name)
    assert found is None, f"expected no application named {app_name!r} to exist, found {found!r}"

    # positive control: a valid AppBlockArn succeeds
    appblock_name = ctx.unique_name("sim2real-appstream-appblock-")
    _put_object(ctx, bucket, "pkg/app.zip")
    appblock_arn = appstream.create_app_block(
        Name=appblock_name,
        PackagingType="APPSTREAM2",
        SourceS3Location={"S3Bucket": bucket, "S3Key": "pkg/app.zip"},
        Tags={"sim2real:managed": "true"},
    )["AppBlock"]["Arn"]
    ctx.on_cleanup(lambda: appstream.delete_app_block(Name=appblock_name))

    app_arn = appstream.create_application(
        Name=app_name,
        IconS3Location={"S3Bucket": bucket, "S3Key": "icons/app.png"},
        LaunchPath="C:\\app\\app.exe",
        Platforms=["WINDOWS_SERVER_2019"],
        InstanceFamilies=["GENERAL_PURPOSE"],
        AppBlockArn=appblock_arn,
        Tags={"sim2real:managed": "true"},
    )["Application"]["Arn"]
    ctx.on_cleanup(lambda: appstream.delete_application(Name=app_name))

    described = appstream.describe_applications(Arns=[app_arn])["Applications"]
    assert len(described) == 1, (
        f"expected exactly 1 application at arn {app_arn!r}, found {len(described)}"
    )


def _create_asset_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-appstream-assets-").lower().replace("_", "-")
    region = ctx.region
    if region == "us-east-1":
        # S3 rejects an explicit LocationConstraint in this one region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})
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


def _find_application_by_name(appstream, name: str):
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = appstream.describe_applications(**kwargs)
        for app in resp["Applications"]:
            if app["Name"] == name:
                return app
        next_token = resp.get("NextToken")
        if not next_token:
            return None


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


