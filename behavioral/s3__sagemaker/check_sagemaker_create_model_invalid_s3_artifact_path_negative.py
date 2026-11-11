"""sagemaker-create-model-invalid-s3-artifact-path-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "sagemaker-create-model-invalid-s3-artifact-path-negative"
GROUP = "overly-permissive"
SERVICES = ["s3", "sagemaker"]

# AWS-owned ECR registry account publishing the built-in linear-learner algorithm image,
# one per region -- this is AWS's own region-to-account mapping, not an assumption about
# this check's operating region.
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateModel with a ModelDataUrl key that was never written in the bucket raises a ClientError, while
    the same CreateModel with the existing key succeeds and DescribeModel echoes that ModelDataUrl."""
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

    real_artifact = _upload_object(ctx, bucket, "model/artifact.tar.gz", b"sim2real-dummy-model-bytes")
    bogus_artifact = f"s3://{bucket}/model/does-not-exist-{ctx.unique_name('x')}.tar.gz"

    # (a) the effect (a successfully-created model pointing at real data) is
    # absent -- CreateModel on a nonexistent key must raise, not accept.
    raised = False
    try:
        _create_model_with_retry(ctx, image_uri, bogus_artifact, role_arn)
    except Exception as exc:  # noqa: BLE001 - asserting on the real ClientError below
        raised = True
        msg = str(exc)
        assert "ValidationException" in msg or "does not exist" in msg or "Could not" in msg, (
            f"CreateModel on a nonexistent S3 key failed, but not with the expected "
            f"validation-style error: {msg!r}"
        )
    assert raised, "CreateModel succeeded against a nonexistent S3 ModelDataUrl -- it must fail"

    # (b) in-file positive control: the exact same bucket/role with a real key works.
    model_good = _create_model_with_retry(ctx, image_uri, real_artifact, role_arn)
    sm = ctx.client("sagemaker")
    desc = sm.describe_model(ModelName=model_good)
    assert desc["PrimaryContainer"]["ModelDataUrl"] == real_artifact, (
        f"positive control: DescribeModel did not echo back the real ModelDataUrl: "
        f"{desc['PrimaryContainer']['ModelDataUrl']!r} != {real_artifact!r}"
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
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": "create-model-invalid-s3-artifact-path"}]},
    )
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
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "create-model-invalid-s3-artifact-path"}],
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
    """Retry only the IAM-role-propagation window, NOT a genuine missing-key error.

    "Could not access model data" is the same transient shape as role
    propagation elsewhere (the role's S3 grant hasn't fanned out yet) and is
    safe to retry. "Could not find model data" means the key genuinely does
    not exist -- for the bogus-artifact path in this check that IS the
    rejection under test, so it must propagate to the caller immediately,
    not be swallowed here.
    """
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
                    "Unable to assume",
                    "Could not assume role",
                    "Could not access model data",
                )
            ):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None, "retry loop exited with no exception recorded and no return value"
    raise last_exc


def _create_model_with_retry(ctx, image_uri: str, model_data_url: str, role_arn: str) -> str:
    """CreateModel, retrying ONLY the role-assumption propagation window.

    "Could not access model data" / "Could not find model data" are not retried: they are the
    rejection asserted for the bogus-key path, so they propagate to the caller.
    """
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-sm-model-")

    def _create():
        sm.create_model(
            ModelName=name,
            PrimaryContainer={"Image": image_uri, "ModelDataUrl": model_data_url},
            ExecutionRoleArn=role_arn,
            Tags=[{"Key": "sim2real", "Value": "create-model-invalid-s3-artifact-path"}],
        )

    _call_with_role_propagation_retry(_create)
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
