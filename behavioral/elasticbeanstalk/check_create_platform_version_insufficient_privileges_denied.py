"""create-platform-version-insufficient-privileges-denied."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-platform-version-insufficient-privileges-denied"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:elasticbeanstalk-custom-platform-quota")
def run(ctx) -> None:
    """CreatePlatformVersion fetches the bundle with the caller's credentials, so a caller without
    s3:GetObject on it fails InvalidParameterValue (S3 Forbidden) and no platform version is
    created, while a caller with read access to the same object can read it."""
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    platform_name = ctx.unique_name("sim2real-beh-platform-")
    bucket = ctx.unique_name("sim2real-eb-platbundle-").lower()
    key = "platform.zip"
    bundle_bytes = _trivial_zip_bytes()

    _create_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key=key, Body=bundle_bytes)

    restricted_role_arn = _create_restricted_role(
        ctx, iam, account_id,
        allow_actions=["elasticbeanstalk:*"],
        deny_statements=[{
            "Effect": "Deny",
            "Action": ["s3:GetObject", "s3:GetObjectVersion"],
            "Resource": f"arn:aws:s3:::{bucket}/{key}",
        }],
    )
    restricted_eb = _assume_role_client(ctx, sts, "elasticbeanstalk", restricted_role_arn)
    _wait_for_active(lambda: restricted_eb.describe_applications())

    code, message = _error_code_and_message(
        lambda: restricted_eb.create_platform_version(
            PlatformName=platform_name,
            PlatformVersion="1.0.0",
            PlatformDefinitionBundle={"S3Bucket": bucket, "S3Key": key},
        )
    )
    assert code == "InvalidParameterValue", f"{code}: {message}"
    expected = (
        f"Unable to download from S3 location (Bucket: {bucket}  Key: {key}). "
        f"Reason: Forbidden: S3Bucket={bucket}, S3Key={key}"
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Effect absent: no platform version with this name exists.
    platforms = eb.list_platform_versions(
        Filters=[{"Type": "PlatformName", "Operator": "=", "Values": [platform_name]}]
    )["PlatformSummaryList"]
    assert platforms == []

    # Positive control: a caller with read access to the exact same bundle can read it.
    obj = s3.get_object(Bucket=bucket, Key=key)
    assert obj["Body"].read() == bundle_bytes


def _trivial_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("placeholder.txt", "sim2real-behavioral-placeholder")
    return buf.getvalue()


def _error_code_and_message(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target accepting what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_bucket(ctx, s3, bucket):
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})


def _empty_and_delete_bucket(s3, bucket):
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_restricted_role(ctx, iam, account_id, allow_actions, deny_statements):
    role_name = ctx.unique_name("sim2real-ebrestrict-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    statements = [{"Effect": "Allow", "Action": allow_actions, "Resource": "*"}] + list(deny_statements)
    policy_doc = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName="restricted", PolicyDocument=json.dumps(policy_doc))
    return f"arn:aws:iam::{account_id}:role/{role_name}"


def _delete_role(iam, role_name):
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _assume_role_client(ctx, sts, service_name, role_arn, timeout_s=90.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-behav")["Credentials"]
            return ctx.client(
                service_name,
                creds={
                    "aws_access_key_id": creds["AccessKeyId"],
                    "aws_secret_access_key": creds["SecretAccessKey"],
                    "aws_session_token": creds["SessionToken"],
                },
            )
        except Exception as e:
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"could not assume restricted role {role_arn}: {last_err}")


def _wait_for_active(probe, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            probe()
            return
        except Exception as e:
            last_err = e
            time.sleep(interval_s)
    raise AssertionError(f"restricted role's attached policy never became active: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
