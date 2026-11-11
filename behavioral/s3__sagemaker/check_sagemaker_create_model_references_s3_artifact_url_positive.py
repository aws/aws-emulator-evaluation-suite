"""sagemaker-create-model-references-s3-artifact-url-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sagemaker-create-model-references-s3-artifact-url-positive"
GROUP = "arn-resolution"
SERVICES = ["s3", "sagemaker"]

_MANAGED_TAG = {"Key": "sim2real:managed", "Value": "true"}

# AWS-owned per-region ECR registry account ids that host the SageMaker built-in
# linear-learner algorithm image -- a fixed AWS reference table, not this check's region.
_LINEAR_LEARNER_ACCOUNTS = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "712309505854",
    "ap-south-1": "991648021394",
    "eu-west-1": "438346466558",
    "eu-west-2": "644912444149",
    "eu-central-1": "664544806723",
    "ca-central-1": "469771592824",
    "sa-east-1": "855470959533",
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModel succeeds for a ModelDataUrl naming an S3 object the role can read, and DescribeModel
    returns exactly that URI, not a normalized one (SageMaker checks the object at CreateModel time)."""
    image_uri = _linear_learner_image(ctx.region)
    bucket = _create_bucket(ctx)

    role_arn = _create_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
                "Resource": "*",
            },
        ],
    )

    artifact_uri = _upload_object(ctx, bucket, "model/artifact.tar.gz", b"sim2real-dummy-model-bytes")

    model_name = _create_model_with_retry(ctx, image_uri, artifact_uri, role_arn)

    sm = ctx.client("sagemaker")
    desc = sm.describe_model(ModelName=model_name)
    assert desc["PrimaryContainer"]["ModelDataUrl"] == artifact_uri, (
        f"DescribeModel ModelDataUrl {desc['PrimaryContainer']['ModelDataUrl']!r} does not match "
        f"the exact S3 artifact URI used at CreateModel time {artifact_uri!r}"
    )


def _linear_learner_image(region: str) -> str:
    account = _LINEAR_LEARNER_ACCOUNTS.get(region)
    if account is None:
        raise AssertionError(f"no known linear-learner ECR registry account mapped for region {region}")
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:1"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-s3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [_MANAGED_TAG]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_role(ctx, statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[_MANAGED_TAG]
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    iam.put_role_policy(
        RoleName=name,
        PolicyName="sim2real-inline",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return role["Arn"]


def _delete_role(ctx, name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pol in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _upload_object(ctx, bucket: str, key: str, body: bytes) -> str:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    return f"s3://{bucket}/{key}"


def _call_with_role_propagation_retry(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - IAM role propagation is eventually consistent
            msg = str(exc)
            if any(
                tok in msg
                for tok in (
                    "is not authorized",
                    "cannot be assumed",
                    "does not exist",
                    "Unable to assume",
                    "Could not assume role",
                    "Could not access model data",
                )
            ):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _create_model_with_retry(ctx, image_uri: str, model_data_url: str, role_arn: str) -> str:
    """CreateModel, retrying while the just-created role's S3 grant propagates.

    Real AWS validates ModelDataUrl access synchronously using the execution
    role, so a role created moments ago can transiently 403/404 here even
    though the policy is objectively correct -- exactly the same eventual
    consistency window as IAM-role-to-compute-service propagation elsewhere.
    """
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-sm-model-")

    def _create():
        sm.create_model(
            ModelName=name,
            PrimaryContainer={"Image": image_uri, "ModelDataUrl": model_data_url},
            ExecutionRoleArn=role_arn,
            Tags=[_MANAGED_TAG],
        )

    _call_with_role_propagation_retry(_create)
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
