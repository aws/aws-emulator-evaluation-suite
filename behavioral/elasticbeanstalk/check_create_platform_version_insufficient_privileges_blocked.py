"""create-platform-version-insufficient-privileges-blocked."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-platform-version-insufficient-privileges-blocked"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:elasticbeanstalk-custom-platform-quota")
def run(ctx) -> None:
    """A CreatePlatformVersion caller denied s3:GetObject on the bundle gets InvalidParameterValue
    with an S3 Forbidden message and registers no platform; a full-privilege caller creates one."""

    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    bucket = eb.create_storage_location()["S3Bucket"]
    key = f"{ctx.unique_name('sim2real-eb-platform-bundle-')}/bundle.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=_platform_bundle_zip())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    restricted, _restricted_arn = _create_restricted_caller(
        ctx,
        allow_actions=["elasticbeanstalk:*", "s3:ListBucket"],
        deny_statements=[{"Effect": "Deny", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket}/{key}"}],
        name_hint="platform",
    )

    denied_platform_name = ctx.unique_name("sim2real-eb-plat-denied-")

    def _create_restricted():
        restricted.create_platform_version(
            PlatformName=denied_platform_name,
            PlatformVersion="1.0.0",
            PlatformDefinitionBundle={"S3Bucket": bucket, "S3Key": key},
        )

    # CreatePlatformVersion synchronously fetches the bundle from S3 as part of validating
    # it, and that fetch runs under the CALLING principal's own permissions, not a service
    # role. A denied s3:GetObject on the bundle therefore never
    # reaches a distinct InsufficientPrivilegesException; it comes back as the same generic
    # InvalidParameterValue code the model documents for a malformed bundle, distinguishable
    # only by the message naming the S3 fetch as Forbidden.
    try:
        _create_restricted()
        raise AssertionError("expected CreatePlatformVersion to reject the denied caller, but it succeeded")
    except ClientError as exc:
        error = exc.response["Error"]
    assert error["Code"] == "InvalidParameterValue", f"expected InvalidParameterValue, got {error['Code']!r}"
    expected = (
        f"Unable to download from S3 location (Bucket: {bucket}  Key: {key}). "
        f"Reason: Forbidden: S3Bucket={bucket}, S3Key={key}"
    )
    assert error["Message"] == expected, (
        f"expected the S3 fetch itself to be reported Forbidden as {expected!r}, "
        f"got: {error['Message']!r}"
    )

    registered = eb.list_platform_versions(
        Filters=[{"Type": "PlatformName", "Operator": "=", "Values": [denied_platform_name]}]
    )["PlatformSummaryList"]
    assert registered == []

    # Positive control: full-privilege caller is authorized to fetch the bundle and start the build.
    allowed_platform_name = ctx.unique_name("sim2real-eb-plat-allowed-")
    resp = eb.create_platform_version(
        PlatformName=allowed_platform_name,
        PlatformVersion="1.0.0",
        PlatformDefinitionBundle={"S3Bucket": bucket, "S3Key": key},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    platform_arn = resp["PlatformSummary"]["PlatformArn"]
    ctx.on_cleanup(lambda: _delete_platform(eb, platform_arn))
    assert platform_arn

    # Terminal read: an independent DescribePlatformVersion call, not the mutating call's
    # own response, confirms the platform record the privileged caller was allowed to create.
    described = eb.describe_platform_version(PlatformArn=platform_arn)["PlatformDescription"]
    assert described["PlatformArn"] == platform_arn
    assert described["PlatformName"] == allowed_platform_name


def _platform_bundle_zip() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("platform.yaml", "version: \"1.0\"\nprovisioner:\n  type: packer\n  template: builder.json\n")
        zf.writestr(
            "builder.json",
            json.dumps(
                {
                    "builders": [
                        {
                            "type": "amazon-ebs",
                            "source_ami_filter": {
                                "filters": {"name": "amzn2-ami-hvm-*-x86_64-gp2"},
                                "owners": ["amazon"],
                                "most_recent": True,
                            },
                            "instance_type": "t3.micro",
                            "ssh_username": "ec2-user",
                            "ami_name": "sim2real-eb-platform-{{timestamp}}",
                        }
                    ]
                }
            ),
        )
    return buf.getvalue()


def _delete_platform(eb, platform_arn: str, timeout_s: float = 840.0) -> None:
    """Delete a custom platform once its build is terminal, retrying OperationInProgressFailure
    every 2 s; a Deleting/Deleted or not-found platform is already gone, anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            status = eb.describe_platform_version(PlatformArn=platform_arn)["PlatformDescription"]["PlatformStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "InvalidParameterValue" and "found" in err.get("Message", "").lower():
                return
            raise
        if status in ("Deleting", "Deleted"):
            return
        if status in ("Ready", "Failed"):
            try:
                eb.delete_platform_version(PlatformArn=platform_arn)
                return
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "OperationInProgressFailure":
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"platform {platform_arn} still {status!r} after {timeout_s}s, not deleted")
        time.sleep(2)


def _create_restricted_caller(ctx, allow_actions, deny_statements, name_hint):
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name(f"sim2real-eb-restr-{name_hint}-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": allow_actions, "Resource": "*"}] + deny_statements,
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="restricted", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="restricted"))
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"

    deadline = time.monotonic() + 60.0
    creds = None
    while time.monotonic() < deadline:
        try:
            creds = sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-eb")["Credentials"]
            break
        except ClientError:
            time.sleep(3.0)
    if creds is None:
        raise AssertionError("could not assume the restricted-privilege IAM role within 60s")

    client = ctx.client(
        "elasticbeanstalk",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )
    return client, role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
