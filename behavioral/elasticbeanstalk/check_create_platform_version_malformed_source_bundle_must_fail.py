"""create-platform-version-malformed-source-bundle-must-fail."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "create-platform-version-malformed-source-bundle-must-fail"
GROUP = "overly-permissive"
SERVICES = ["elasticbeanstalk"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:elasticbeanstalk-custom-platform-quota")
def run(ctx) -> None:
    """CreatePlatformVersion with a bundle that lacks a platform.yaml manifest returns PlatformStatus "Creating",
    then the platform version reaches "Failed" without a build."""
    iam = ctx.client("iam")
    eb = ctx.client("elasticbeanstalk")
    s3 = ctx.client("s3")

    svc_role, ec2_profile = _ensure_builder_iam(ctx, iam)

    bucket = eb.create_storage_location()["S3Bucket"]
    key = ctx.unique_name("sim2real-eb-platform-") + ".zip"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        # Deliberately no platform.yaml manifest at the bundle root.
        zf.writestr("README.txt", "not a valid Elastic Beanstalk custom platform bundle")
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    platform_name = ctx.unique_name("sim2real-custom-platform-")
    resp = eb.create_platform_version(
        PlatformName=platform_name,
        PlatformVersion="1.0.0",
        PlatformDefinitionBundle={"S3Bucket": bucket, "S3Key": key},
        Tags=[{"Key": "sim2real", "Value": "true"}],
        OptionSettings=[
            {
                "Namespace": "aws:elasticbeanstalk:environment",
                "OptionName": "ServiceRole",
                "Value": svc_role,
            },
            {
                "Namespace": "aws:autoscaling:launchconfiguration",
                "OptionName": "IamInstanceProfile",
                "Value": ec2_profile,
            },
        ],
    )
    arn = resp["PlatformSummary"]["PlatformArn"]
    ctx.on_cleanup(lambda: eb.delete_platform_version(PlatformArn=arn))

    # The synchronous call itself must be accepted (not unconditionally rejected) -- this is
    # the "positive" half proving the eventual failure below is a real build-time validation,
    # not blanket API rejection of CreatePlatformVersion.
    assert resp["PlatformSummary"]["PlatformStatus"] == "Creating", (
        f"CreatePlatformVersion returned status {resp['PlatformSummary']['PlatformStatus']!r}; "
        "expected the synchronous call to be accepted with status 'Creating'"
    )
    status = _poll_platform_status(eb, arn, timeout_s=1500.0, interval_s=30.0)
    assert status == "Failed", (
        f"platform version reached status {status!r} for a bundle with no manifest; "
        "expected the build to fail, not report success"
    )


def _ensure_builder_iam(ctx, iam) -> tuple[str, str]:
    """Create a check-scoped service role + EC2 instance profile for the platform builder
    environment, torn down in cleanup, passed through CreatePlatformVersion's OptionSettings: a new
    account has no aws-elasticbeanstalk-service-role / aws-elasticbeanstalk-ec2-role by default."""
    suffix = ctx.unique_name("sim2real-eb-platbuild-")
    svc_name = f"{suffix}-svc"
    ec2_name = f"{suffix}-ec2"

    def _trust(service: str) -> str:
        return json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole"}],
            }
        )

    tags = [{"Key": "sim2real", "Value": "true"}]
    iam.create_role(
        RoleName=svc_name, AssumeRolePolicyDocument=_trust("elasticbeanstalk.amazonaws.com"), Tags=tags
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=svc_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/service-role/AWSElasticBeanstalkEnhancedHealth",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy",
    ):
        iam.attach_role_policy(RoleName=svc_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=svc_name, PolicyArn=p))

    iam.create_role(RoleName=ec2_name, AssumeRolePolicyDocument=_trust("ec2.amazonaws.com"), Tags=tags)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=ec2_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkWebTier",
        "arn:aws:iam::aws:policy/AWSElasticBeanstalkWorkerTier",
    ):
        iam.attach_role_policy(RoleName=ec2_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=ec2_name, PolicyArn=p))

    iam.create_instance_profile(InstanceProfileName=ec2_name, Tags=tags)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=ec2_name))
    iam.add_role_to_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=ec2_name, RoleName=ec2_name))

    return svc_name, ec2_name


def _poll_platform_status(eb, arn, timeout_s=1500.0, interval_s=30.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = eb.describe_platform_version(PlatformArn=arn)["PlatformDescription"]["PlatformStatus"]
        if status in ("Ready", "Failed"):
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"platform version {arn} did not reach a terminal status within {timeout_s}s; last status={status!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
