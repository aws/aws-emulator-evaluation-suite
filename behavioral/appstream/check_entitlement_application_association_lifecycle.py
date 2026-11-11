"""entitlement-application-association-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "entitlement-application-association-lifecycle"
GROUP = "lifecycle"
SERVICES = ["appstream"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Associating an app with an entitlement makes it visible via ListEntitledApplications,
    disassociating removes it, and a duplicate Name+StackName entitlement is rejected."""
    appstream = ctx.client("appstream")
    bucket = _create_asset_bucket(ctx)
    _put_object(ctx, bucket, "pkg/app.zip")
    _put_object(ctx, bucket, "icons/app.png")

    stack_name = ctx.unique_name("sim2real-appstream-stack-")
    appstream.create_stack(Name=stack_name, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: appstream.delete_stack(Name=stack_name))

    appblock_name = ctx.unique_name("sim2real-appstream-appblock-")
    appblock_arn = appstream.create_app_block(
        Name=appblock_name,
        PackagingType="APPSTREAM2",
        SourceS3Location={"S3Bucket": bucket, "S3Key": "pkg/app.zip"},
        Tags={"sim2real-check": CHECK},
    )["AppBlock"]["Arn"]
    ctx.on_cleanup(lambda: appstream.delete_app_block(Name=appblock_name))

    app_name = ctx.unique_name("sim2real-appstream-app-")
    app_arn = appstream.create_application(
        Name=app_name,
        IconS3Location={"S3Bucket": bucket, "S3Key": "icons/app.png"},
        LaunchPath="C:\\app\\app.exe",
        Platforms=["WINDOWS_SERVER_2019"],
        InstanceFamilies=["GENERAL_PURPOSE"],
        AppBlockArn=appblock_arn,
        Tags={"sim2real-check": CHECK},
    )["Application"]["Arn"]
    ctx.on_cleanup(lambda: appstream.delete_application(Name=app_name))

    original_attributes = [{"Name": "roles", "Value": "test-role"}]
    entitlement_name = ctx.unique_name("sim2real-appstream-ent-")
    appstream.create_entitlement(
        Name=entitlement_name,
        StackName=stack_name,
        AppVisibility="ASSOCIATED",
        Attributes=original_attributes,
    )
    ctx.on_cleanup(lambda: appstream.delete_entitlement(Name=entitlement_name, StackName=stack_name))

    # duplicate Name+StackName entitlement is rejected (uniqueness boundary)
    code, message = _error(
        lambda: appstream.create_entitlement(
            Name=entitlement_name,
            StackName=stack_name,
            AppVisibility="ASSOCIATED",
            Attributes=[{"Name": "roles", "Value": "other-role"}],
        )
    )
    assert code == "EntitlementAlreadyExistsException", f"expected EntitlementAlreadyExistsException, got {code!r}"
    expected_message = "The requested entitlement already exists."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the loser's Attributes did not overwrite the original entitlement
    described = appstream.describe_entitlements(StackName=stack_name, Name=entitlement_name)[
        "Entitlements"
    ][0]
    assert described["Attributes"] == original_attributes, (
        f"expected original attributes {original_attributes!r} untouched by the losing create, "
        f"got {described['Attributes']!r}"
    )

    appstream.associate_application_to_entitlement(
        StackName=stack_name, EntitlementName=entitlement_name, ApplicationIdentifier=app_arn
    )

    entitled = appstream.list_entitled_applications(StackName=stack_name, EntitlementName=entitlement_name)[
        "EntitledApplications"
    ]
    assert any(e["ApplicationIdentifier"] == app_arn for e in entitled), (
        f"expected {app_arn!r} in ListEntitledApplications after associate, got {entitled!r}"
    )

    appstream.disassociate_application_from_entitlement(
        StackName=stack_name, EntitlementName=entitlement_name, ApplicationIdentifier=app_arn
    )
    entitled_after = appstream.list_entitled_applications(
        StackName=stack_name, EntitlementName=entitlement_name
    )["EntitledApplications"]
    assert not any(e["ApplicationIdentifier"] == app_arn for e in entitled_after), (
        f"expected {app_arn!r} absent from ListEntitledApplications after disassociate, got {entitled_after!r}"
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
    import json

    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

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
