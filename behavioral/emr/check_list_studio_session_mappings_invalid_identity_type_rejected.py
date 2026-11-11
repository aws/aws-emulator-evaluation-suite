"""list-studio-session-mappings-invalid-identity-type-rejected."""
from __future__ import annotations

import json
import time

import botocore.exceptions
from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-studio-session-mappings-invalid-identity-type-rejected"
GROUP = "overly-permissive"
SERVICES = ["emr"]


def _service_message(text, message, service="AWSEditors"):
    """`text` as the EMR backend `service` words a refusal; only its per-call request id is taken
    from the actual message."""
    request_id = (message or "").rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    return (
        f"{text} (Service: {service}; Status Code: 400; Error Code: InvalidRequestException; "
        f"Request ID: {request_id}; Proxy: null)"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListStudioSessionMappings with an out-of-enum IdentityType fails with InvalidRequestException,
    HTTP 400 and AWS's exact message, while a valid IdentityType on the same Studio returns an empty
    list."""
    emr = ctx.client("emr")
    studio_id = _create_studio(ctx)

    # negative: IdentityType is an enum restricted to USER|GROUP
    code, status, message = _error(
        lambda: emr.list_studio_session_mappings(StudioId=studio_id, IdentityType="SUPERUSER")
    )
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
    assert status == 400, f"expected HTTP 400, got {status!r}"
    expected = _service_message("IdentityType is not valid.", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    # Positive control: a valid IdentityType on the same Studio still succeeds.
    resp = emr.list_studio_session_mappings(StudioId=studio_id, IdentityType="USER")
    assert resp["SessionMappings"] == [], f"expected no mappings on a fresh Studio, got {resp['SessionMappings']}"

    described = emr.describe_studio(StudioId=studio_id)["Studio"]
    assert described["StudioId"] == studio_id


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("InvalidGroup.NotFound", "InvalidSubnetID.NotFound", "InvalidVpcID.NotFound", "NoSuchBucket", "NoSuchEntity")
            and not (err["Code"] == "InvalidRequestException" and "does not exist" in err.get("Message", ""))
        ):
            raise


def _error(fn):
    """Call fn() and return its ClientError (code, HTTP status, message); an unexpected success raises."""
    try:
        result = fn()
    except botocore.exceptions.ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], exc.response["ResponseMetadata"]["HTTPStatusCode"], error.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _create_studio(ctx) -> str:
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    emr = ctx.client("emr")

    vpc_id = ec2.create_vpc(CidrBlock="10.91.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-emr-studio-vpc-")}])

    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.91.1.0/24")["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_subnet(SubnetId=subnet_id)))

    workspace_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-ws-"), Description="workspace sg", VpcId=vpc_id
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_security_group(GroupId=workspace_sg)))

    engine_sg = ec2.create_security_group(
        GroupName=ctx.unique_name("sim2real-emr-studio-eng-"), Description="engine sg", VpcId=vpc_id
    )["GroupId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_security_group(GroupId=engine_sg)))

    bucket = ctx.unique_name("sim2real-emr-studio-").lower()
    # S3 rejects an explicit LocationConstraint for us-east-1.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _safe(lambda: s3.delete_bucket(Bucket=bucket)))

    role_name = ctx.unique_name("sim2real-emr-studio-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "elasticmapreduce.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))

    s3_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:PutObject",
                    "s3:DeleteObject",
                    "s3:ListBucket",
                    "s3:GetBucketLocation",
                    "s3:GetEncryptionConfiguration",
                ],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    policy_name = ctx.unique_name("sim2real-emr-studio-s3-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(s3_policy),
    )
    # Cleanups run LIFO: the inline policy goes before delete_role, which IAM refuses otherwise.
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)))
    # IAM role/policy propagation is eventually consistent; retry CreateStudio until it succeeds.
    studio_id = _retry_create_studio(
        ctx,
        emr,
        Name=ctx.unique_name("sim2real-emr-studio-"),
        AuthMode="IAM",
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        ServiceRole=role_arn,
        WorkspaceSecurityGroupId=workspace_sg,
        EngineSecurityGroupId=engine_sg,
        DefaultS3Location=f"s3://{bucket}/studio/",
    )
    ctx.on_cleanup(lambda: _safe(lambda: emr.delete_studio(StudioId=studio_id)))
    return studio_id


def _retry_create_studio(ctx, emr, **kwargs) -> str:
    """CreateStudio, retried every 2 s for up to 60 s while IAM propagates the new service role."""
    left = ctx.time_left()
    deadline = time.monotonic() + (60.0 if left is None else min(60.0, left))
    while True:
        try:
            return emr.create_studio(**kwargs)["StudioId"]
        except botocore.exceptions.ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidRequestException" or time.monotonic() >= deadline:
                raise
            time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

