"""stack-theme-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "stack-theme-lifecycle"
GROUP = "lifecycle"
SERVICES = ["appstream"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateThemeForStack persists theme content, UpdateThemeForStack flips
    ENABLED/DISABLED, and DeleteThemeForStack removes it (subsequent describe fails)."""
    appstream = ctx.client("appstream")
    bucket = _create_asset_bucket(ctx)
    _put_object(ctx, bucket, "theme/logo.png")
    _put_object(ctx, bucket, "theme/favicon.ico")

    stack_name = ctx.unique_name("sim2real-appstream-stack-")
    appstream.create_stack(Name=stack_name, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: appstream.delete_stack(Name=stack_name))

    theme = _retry_s3_propagation(
        lambda: appstream.create_theme_for_stack(
            StackName=stack_name,
            TitleText="Sim2Real Test Theme",
            ThemeStyling="BLUE",
            OrganizationLogoS3Location={"S3Bucket": bucket, "S3Key": "theme/logo.png"},
            FaviconS3Location={"S3Bucket": bucket, "S3Key": "theme/favicon.ico"},
        )
    )["Theme"]
    assert theme["ThemeTitleText"] == "Sim2Real Test Theme", (
        f"expected create_theme_for_stack to echo the submitted title, got {theme['ThemeTitleText']!r}"
    )
    ctx.on_cleanup(lambda: _delete_theme_if_present(appstream, stack_name))

    described = appstream.describe_theme_for_stack(StackName=stack_name)["Theme"]
    assert described["State"] == "ENABLED", (
        f"expected a freshly created theme to describe as ENABLED, got {described['State']!r}"
    )

    updated = appstream.update_theme_for_stack(StackName=stack_name, State="DISABLED")["Theme"]
    assert updated["State"] == "DISABLED", (
        f"expected update_theme_for_stack(State=DISABLED) to report DISABLED, got {updated['State']!r}"
    )

    described_after = appstream.describe_theme_for_stack(StackName=stack_name)["Theme"]
    assert described_after["State"] == "DISABLED", (
        f"expected the DISABLED state to persist across an independent describe, got "
        f"{described_after['State']!r}"
    )

    appstream.delete_theme_for_stack(StackName=stack_name)

    code, message = _error(lambda: appstream.describe_theme_for_stack(StackName=stack_name))
    assert code == "ResourceNotFoundException", (
        f"expected describe_theme_for_stack on a deleted theme to raise ResourceNotFoundException, "
        f"got {code!r}"
    )
    expected_message = f"The theme for stack {stack_name} for account {ctx.account}  does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    update_code, update_message = _error(
        lambda: appstream.update_theme_for_stack(StackName=stack_name, State="ENABLED")
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected a mutation on the deleted theme to also raise ResourceNotFoundException, "
        f"got {update_code!r}"
    )
    assert update_message == expected_message, (
        f"expected message {expected_message!r}, got {update_message!r}"
    )


def _retry_s3_propagation(fn, timeout_s: float = 60.0):
    """Retry fn() while AppStream reports it cannot yet see/own the just-created S3
    object (cross-service S3 read propagation shortly after PutObject)."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            msg = err.response["Error"].get("Message", "")
            if (
                err.response["Error"]["Code"] != "InvalidParameterValueException"
                or "S3 object" not in msg
                and "does not own" not in msg
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(5)


def _create_asset_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-appstream-assets-").lower().replace("_", "-")
    region = ctx.region
    # us-east-1 rejects an explicit LocationConstraint on CreateBucket; every other region requires one.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    # AppStream reads these objects via ACL-based ownership checks; ACLs are disabled by
    # default on new buckets (BucketOwnerEnforced), so opt back into BucketOwnerPreferred.
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


def _delete_theme_if_present(appstream, stack_name: str) -> None:
    """Teardown: the check body deletes the theme itself, so a not-found here is the clean case."""
    from botocore.exceptions import ClientError

    try:
        appstream.delete_theme_for_stack(StackName=stack_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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

