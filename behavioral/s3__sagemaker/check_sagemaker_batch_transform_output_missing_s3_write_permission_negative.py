"""sagemaker-batch-transform-output-missing-s3-write-permission-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-batch-transform-output-missing-s3-write-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]

_LINEAR_LEARNER_ACCOUNTS = {
    "us-east-1": "382416733822", "us-east-2": "404615174143", "us-west-1": "632365934929",
    "us-west-2": "174872318107", "ap-northeast-1": "351501993468", "ap-northeast-2": "835164637446",
    "ap-southeast-1": "475088953585", "ap-southeast-2": "712309505854", "ap-south-1": "991648021394",
    "eu-west-1": "438346466558", "eu-west-2": "644912444149", "eu-central-1": "664544806723",
    "ca-central-1": "469771592824", "sa-east-1": "855470959533",
}


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A transform job whose model role lacks s3:PutObject on the output bucket is accepted but
    ends Failed with no output object, while an identical job with the grant completes and writes.
    """
    image_uri = _linear_learner_image(ctx.region)
    bucket_model = _create_bucket(ctx)
    bucket_input = _create_bucket(ctx)
    bucket_output = _create_bucket(ctx)

    train_uri = _upload_csv(ctx, bucket_model, "train/data.csv", [[3 * x + 2, x] for x in range(1, 21)])

    train_role = _create_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                "Resource": [f"arn:aws:s3:::{bucket_model}", f"arn:aws:s3:::{bucket_model}/*"],
            },
            _logs_statement(),
        ],
    )
    _job, artifact = _run_training_job(ctx, train_role, image_uri, train_uri, f"s3://{bucket_model}/model/", feature_dim=1)

    input_uri = _upload_csv(ctx, bucket_input, "input/records.csv", [[x] for x in range(1, 6)])

    read_statement = {
        "Effect": "Allow",
        "Action": ["s3:GetObject", "s3:ListBucket"],
        "Resource": [
            f"arn:aws:s3:::{bucket_model}",
            f"arn:aws:s3:::{bucket_model}/*",
            f"arn:aws:s3:::{bucket_input}",
            f"arn:aws:s3:::{bucket_input}/*",
        ],
    }
    role_good = _create_role(
        ctx,
        [
            read_statement,
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": [f"arn:aws:s3:::{bucket_output}/*"]},
            _logs_statement(),
        ],
    )
    role_bad_write = _create_role(
        ctx,
        [
            read_statement,
            _logs_statement(),
            # Deliberately NO grant on bucket_output -- this is the one boundary being broken.
        ],
    )

    model_good = _create_model(ctx, image_uri, artifact, role_good)
    model_bad_write = _create_model(ctx, image_uri, artifact, role_bad_write)

    bad_status, bad_reason = _run_transform_job(
        ctx, model_bad_write, input_uri, f"s3://{bucket_output}/bad/"
    )
    good_status, good_reason = _run_transform_job(
        ctx, model_good, input_uri, f"s3://{bucket_output}/good/"
    )

    assert bad_status == "Failed", f"transform job with no write grant on the output bucket ended {bad_status}, expected Failed"
    assert bad_reason, "Failed transform job must carry a FailureReason"
    assert not _object_exists(ctx, bucket_output, "bad/records.csv.out"), (
        "transform output was written to S3 even though the model's role never had "
        "s3:PutObject on the output bucket -- the write should never have succeeded"
    )

    assert good_status == "Completed", f"control transform job (full permissions) failed: {good_status} / {good_reason}"
    assert _object_exists(ctx, bucket_output, "good/records.csv.out")


def _logs_statement() -> dict[str, Any]:
    return {
        "Effect": "Allow",
        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
        "Resource": "*",
    }


def _object_exists(ctx, bucket: str, key: str) -> bool:
    s3 = ctx.client("s3")
    try:
        s3.head_object(Bucket=bucket, Key=key)
        return True
    except Exception:
        return False


# ===== helpers =====


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(t in msg for t in ("not found", "does not exist", "could not find"))
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
        iam.delete_role(RoleName=name)
    except ClientError as exc:
        if not _gone(exc):
            raise


def _upload_csv(ctx, bucket: str, key: str, rows: list[list[Any]]) -> str:
    s3 = ctx.client("s3")
    body = "\n".join(",".join(str(v) for v in row) for row in rows) + "\n"
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))
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


def _run_training_job(ctx, role_arn, image_uri, train_s3_uri, output_s3_uri, feature_dim, timeout_s=900.0):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-sm-train-")

    def _start():
        sm.create_training_job(
            TrainingJobName=name,
            AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
            RoleArn=role_arn,
            InputDataConfig=[
                {
                    "ChannelName": "train",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": train_s3_uri,
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                    "ContentType": "text/csv",
                    "CompressionType": "None",
                }
            ],
            OutputDataConfig={"S3OutputPath": output_s3_uri},
            ResourceConfig={"InstanceType": "ml.m4.xlarge", "InstanceCount": 1, "VolumeSizeInGB": 5},
            StoppingCondition={"MaxRuntimeInSeconds": 1800},
            HyperParameters={
                "feature_dim": str(feature_dim),
                "predictor_type": "regressor",
                "mini_batch_size": "4",
                "epochs": "10",
            },
        )

    _call_with_role_propagation_retry(_start)
    ctx.on_cleanup(lambda: _stop_training_job(ctx, name))
    deadline = time.monotonic() + timeout_s
    desc: dict[str, Any] = {}
    status = None
    while time.monotonic() < deadline:
        desc = sm.describe_training_job(TrainingJobName=name)
        status = desc["TrainingJobStatus"]
        if status in ("Completed", "Failed", "Stopped"):
            break
        time.sleep(2)
    if status != "Completed":
        raise AssertionError(f"training job {name} ended in status {status}: {desc.get('FailureReason')}")
    return name, desc["ModelArtifacts"]["S3ModelArtifacts"]


def _stop_training_job(ctx, name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        desc = sm.describe_training_job(TrainingJobName=name)
        if desc["TrainingJobStatus"] in ("InProgress", "Stopping"):
            sm.stop_training_job(TrainingJobName=name)
    except ClientError as exc:
        if not _gone(exc) and (exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=name)["TrainingJobStatus"] == "InProgress"):
            raise


def _create_model(ctx, image_uri: str, model_data_url: str, role_arn: str) -> str:
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


def _run_transform_job(ctx, model_name: str, input_s3_uri: str, output_s3_uri: str, timeout_s: float = 900.0):
    sm = ctx.client("sagemaker")
    name = ctx.unique_name("sim2real-sm-xform-")
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
    ctx.on_cleanup(lambda: _stop_transform_job(ctx, name))
    deadline = time.monotonic() + timeout_s
    desc: dict[str, Any] = {}
    status = "InProgress"
    while time.monotonic() < deadline:
        desc = sm.describe_transform_job(TransformJobName=name)
        status = desc["TransformJobStatus"]
        if status in ("Completed", "Failed", "Stopped"):
            break
        time.sleep(2)
    return status, desc.get("FailureReason")


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
