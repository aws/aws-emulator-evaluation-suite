"""sagemaker-batch-transform-reads-s3-input-positive."""
from __future__ import annotations

import io
import json
import tarfile
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-batch-transform-reads-s3-input-positive"
GROUP = "data-flow"
SERVICES = ["s3", "sagemaker"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateTransformJob lists TransformInput's S3 prefix synchronously: an empty prefix is
    rejected with a no-objects error and no job exists, while the same call against a populated
    prefix is accepted and not Failed."""
    bucket = _create_bucket(ctx)
    artifact_uri = _upload_object(ctx, bucket, "model/artifact.tar.gz", _build_model_tar())
    _upload_object(ctx, bucket, "input_populated/records.csv", b"1\n2\n3\n")

    role_arn = _create_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": [f"arn:aws:s3:::{bucket}/*"]},
            _logs_statement(),
        ],
    )

    model_name = _create_model_with_retry(ctx, _container_image(ctx.region), artifact_uri, role_arn)

    empty_uri = f"s3://{bucket}/input_empty/"
    empty_job_name = ctx.unique_name("sim2real-sm-xform-empty-")
    raised = False
    try:
        _create_transform_job_synchronous(ctx, empty_job_name, model_name, empty_uri, f"s3://{bucket}/out-empty/")
    except Exception as exc:  # noqa: BLE001 - asserting on the real ClientError below
        raised = True
        msg = str(exc)
        assert "No S3 objects found" in msg or "does not exist" in msg, (
            f"CreateTransformJob against an empty S3 prefix failed, but not with the expected "
            f"'no objects found'-style error: {msg!r}"
        )
    assert raised, (
        "CreateTransformJob succeeded pointing at an S3 prefix with ZERO objects under it -- "
        "SageMaker must actually inspect the input path's contents, not accept it blindly"
    )
    listed = ctx.client("sagemaker").list_transform_jobs(NameContains=empty_job_name)
    assert listed["TransformJobSummaries"] == [], (
        f"CreateTransformJob against an empty prefix was rejected, but a job named "
        f"{empty_job_name!r} still appears in ListTransformJobs: {listed['TransformJobSummaries']}"
    )

    populated_uri = f"s3://{bucket}/input_populated/"
    good_job_name = ctx.unique_name("sim2real-sm-xform-good-")
    job_name = _create_transform_job_synchronous(ctx, good_job_name, model_name, populated_uri, f"s3://{bucket}/out-good/")
    assert job_name == good_job_name, f"expected the created job to be named {good_job_name!r}, got {job_name!r}"
    desc = ctx.client("sagemaker").describe_transform_job(TransformJobName=job_name)
    assert desc["TransformJobStatus"] != "Failed", (
        f"CreateTransformJob against a populated S3 prefix should not fail immediately, but "
        f"DescribeTransformJob reports status={desc['TransformJobStatus']!r} reason={desc.get('FailureReason')!r}"
    )


def _container_image(region: str) -> str:
    # Built-in linear-learner image; the validation under test concerns S3 access, not this image.
    accounts = {
        "us-east-1": "382416733822", "us-east-2": "404615174143", "us-west-1": "632365934929",
        "us-west-2": "174872318107", "ap-northeast-1": "351501993468", "ap-northeast-2": "835164637446",
        "ap-southeast-1": "475088953585", "ap-southeast-2": "712309505854", "ap-south-1": "991648021394",
        "eu-west-1": "438346466558", "eu-west-2": "644912444149", "eu-central-1": "664544806723",
        "ca-central-1": "469771592824", "sa-east-1": "855470959533",
    }
    account = accounts.get(region)
    if account is None:
        raise AssertionError(f"no known built-in-algorithm registry account mapped for region {region}")
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:1"


def _logs_statement() -> dict[str, Any]:
    return {
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
        "Resource": "*",
    }


# ===== helpers =====


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket", "RepositoryNotFoundException") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(t in msg for t in ("not found", "does not exist", "could not find"))
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-s3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if not _gone(exc):
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
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
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
        if not _gone(exc):
            raise
    try:
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if not _gone(exc):
            raise


def _upload_object(ctx, bucket: str, key: str, body: bytes) -> str:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    return f"s3://{bucket}/{key}"


def _call_with_role_propagation_retry(fn, retryable_tokens: tuple[str, ...] = (
    "is not authorized", "cannot be assumed", "Unable to assume", "Could not assume role",
    "Could not access model data", "No S3 objects found",
), timeout_s: float = 90.0, interval_s: float = 5.0):
    """Retry while a just-created role's IAM grants and S3 read access propagate.

    "No S3 objects found" is also what a not-yet-propagated role sees on a populated prefix.
    """
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - IAM/S3 propagation is eventually consistent
            msg = str(exc)
            if any(tok in msg for tok in retryable_tokens):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None, f"retry loop for {fn!r} exited at the deadline with no exception recorded"
    raise last_exc


def _create_model_with_retry(ctx, image_uri: str, model_data_url: str, role_arn: str) -> str:
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-sm-model-")

    def _create():
        sm.create_model(
            ModelName=name,
            PrimaryContainer={"Image": image_uri, "ModelDataUrl": model_data_url},
            ExecutionRoleArn=role_arn,
        )

    _call_with_role_propagation_retry(_create)
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=name))
    return name


def _build_model_tar() -> bytes:
    """Minimal gzip tarball; CreateTransformJob rejects a non-gzip ModelDataUrl synchronously."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = b"sim2real-dummy-model-bytes"
        info = tarfile.TarInfo(name="model.bin")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _create_transform_job_synchronous(ctx, name: str, model_name: str, input_s3_uri: str, output_s3_uri: str) -> str:
    """Call CreateTransformJob without waiting; an accepted job is stopped at cleanup.

    The behaviour under test is synchronous, and a full transform run takes many minutes.
    """
    sm = ctx.client("sagemaker")

    def _create():
        sm.create_transform_job(
            TransformJobName=name,
            ModelName=model_name,
            TransformInput={
                "DataSource": {"S3DataSource": {"S3DataType": "S3Prefix", "S3Uri": input_s3_uri}},
                "ContentType": "text/csv",
                "SplitType": "Line",
            },
            TransformOutput={"S3OutputPath": output_s3_uri, "Accept": "application/jsonlines", "AssembleWith": "Line"},
            TransformResources={"InstanceType": "ml.m4.xlarge", "InstanceCount": 1},
        )

    _call_with_role_propagation_retry(_create)
    ctx.on_cleanup(lambda: _stop_transform_job(ctx, name))
    return name


def _stop_transform_job(ctx, name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        desc = sm.describe_transform_job(TransformJobName=name)
        if desc["TransformJobStatus"] == "InProgress":
            sm.stop_transform_job(TransformJobName=name)
    except ClientError as exc:
        if not _gone(exc) and (exc.response["Error"]["Code"] != "ValidationException" or sm.describe_transform_job(TransformJobName=name)["TransformJobStatus"] == "InProgress"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

