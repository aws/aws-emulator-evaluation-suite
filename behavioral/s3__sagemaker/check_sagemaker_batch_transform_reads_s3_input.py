"""sagemaker-batch-transform-reads-s3-input."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-batch-transform-reads-s3-input"
GROUP = "data-ingestion"
SERVICES = ["s3", "sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A batch transform job reads the exact S3 object configured as its input: two jobs on the
    same model with different-sized inputs each complete and emit one numeric score per row."""
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    role_arn = _create_sagemaker_role(
        ctx,
        statements=[
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": [f"arn:aws:s3:::{bucket}/*"]},
        ],
    )
    model_data = _train_linear_learner_model(ctx, bucket, role_arn)
    model_name = _create_transform_model(ctx, role_arn, model_data)

    small_rows = ["0.11,0.21", "0.12,0.22", "0.13,0.23"]
    large_rows = ["0.21,0.31", "0.22,0.32", "0.23,0.33", "0.24,0.34", "0.25,0.35", "0.26,0.36"]
    s3.put_object(Bucket=bucket, Key="transform-input/small.csv", Body=("\n".join(small_rows) + "\n").encode())
    s3.put_object(Bucket=bucket, Key="transform-input/large.csv", Body=("\n".join(large_rows) + "\n").encode())

    job_small = ctx.unique_name("sim2real-sm-tf-small-")
    job_large = ctx.unique_name("sim2real-sm-tf-large-")
    for job_name, key in ((job_small, "small.csv"), (job_large, "large.csv")):
        sm.create_transform_job(
            TransformJobName=job_name,
            ModelName=model_name,
            TransformInput={
                "DataSource": {
                    "S3DataSource": {"S3DataType": "S3Prefix", "S3Uri": f"s3://{bucket}/transform-input/{key}"}
                },
                "ContentType": "text/csv",
                "SplitType": "Line",
            },
            TransformOutput={"S3OutputPath": f"s3://{bucket}/transform-output/", "Accept": "text/csv", "AssembleWith": "Line"},
            TransformResources={"InstanceType": "ml.m5.large", "InstanceCount": 1},
            Tags=[{"Key": "sim2real", "Value": "batch-transform-reads-s3-input"}],
        )

    desc_small = _wait_for_terminal(lambda: sm.describe_transform_job(TransformJobName=job_small), "TransformJobStatus")
    desc_large = _wait_for_terminal(lambda: sm.describe_transform_job(TransformJobName=job_large), "TransformJobStatus")
    assert desc_small["TransformJobStatus"] == "Completed", desc_small.get("FailureReason")
    assert desc_large["TransformJobStatus"] == "Completed", desc_large.get("FailureReason")

    out_small = _get_text(ctx, bucket, "transform-output/small.csv.out").strip().splitlines()
    out_large = _get_text(ctx, bucket, "transform-output/large.csv.out").strip().splitlines()
    assert len(out_small) == len(small_rows), f"expected {len(small_rows)} scores read from small.csv, got {len(out_small)}"
    assert len(out_large) == len(large_rows), f"expected {len(large_rows)} scores read from large.csv, got {len(out_large)}"
    for line in out_small + out_large:
        float(line.strip())  # each row must be a numeric regression score


# AWS-owned per-region ECR accounts hosting the built-in linear-learner image.
LINEAR_LEARNER_ACCOUNT_BY_REGION = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "eu-west-1": "438346466558",
}
LINEAR_LEARNER_TAG = "1"

TRAIN_CSV = (
    "1.0,0.10,0.20\n"
    "2.0,0.20,0.30\n"
    "3.0,0.30,0.40\n"
    "4.0,0.40,0.50\n"
    "5.0,0.50,0.60\n"
    "6.0,0.60,0.70\n"
    "7.0,0.70,0.80\n"
    "8.0,0.80,0.90\n"
)


def _linear_learner_image(region: str) -> str:
    account = LINEAR_LEARNER_ACCOUNT_BY_REGION.get(region)
    if not account:
        raise AssertionError(
            f"no known linear-learner built-in-algorithm ECR account mapped for region {region}; "
            "extend LINEAR_LEARNER_ACCOUNT_BY_REGION to enable this check there"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:{LINEAR_LEARNER_TAG}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sm-s3-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "batch-transform-reads-s3-input"}]}
    )

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_sagemaker_role(ctx, *, statements) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_json_dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "batch-transform-reads-s3-input"}],
    )["Role"]["Arn"]
    policy_name = ctx.unique_name("sim2real-sm-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=_json_dumps({"Version": "2012-10-17", "Statement": statements})
    )

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _json_dumps(obj) -> str:
    import json

    return json.dumps(obj)


def _retry_role_not_ready(create_fn, *, timeout_s: float = 90.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return create_fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException":
                last_exc = exc
                time.sleep(3)
                continue
            raise
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s: float = 900.0, interval_s: float = 20.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not reached within {timeout_s}s; last observed={last!r}")


def _wait_for_terminal(describe_fn, status_key, *, timeout_s: float = 900.0, interval_s: float = 20.0):
    terminal = {"Completed", "Failed", "Stopped"}
    return _poll_until(describe_fn, lambda resp: resp[status_key] in terminal, timeout_s=timeout_s, interval_s=interval_s)


def _get_text(ctx, bucket, key) -> str:
    body = ctx.client("s3").get_object(Bucket=bucket, Key=key)["Body"].read()
    return body.decode("utf-8")


def _train_linear_learner_model(ctx, bucket, role_arn, *, prefix="model") -> str:
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")
    s3.put_object(Bucket=bucket, Key=f"{prefix}/train/data.csv", Body=TRAIN_CSV.encode("utf-8"))
    job_name = ctx.unique_name(f"sim2real-sm-train-{prefix}-")
    image = _linear_learner_image(ctx.region)

    def _create():
        return sm.create_training_job(
            TrainingJobName=job_name,
            AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "File"},
            RoleArn=role_arn,
            InputDataConfig=[
                {
                    "ChannelName": "train",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": f"s3://{bucket}/{prefix}/train/",
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                    "ContentType": "text/csv",
                    "CompressionType": "None",
                }
            ],
            OutputDataConfig={"S3OutputPath": f"s3://{bucket}/{prefix}/training-output/"},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
            StoppingCondition={"MaxRuntimeInSeconds": 1800},
            HyperParameters={"predictor_type": "regressor", "mini_batch_size": "4"},
            Tags=[{"Key": "sim2real", "Value": "batch-transform-reads-s3-input"}],
        )

    _retry_role_not_ready(_create)
    desc = _wait_for_terminal(lambda: sm.describe_training_job(TrainingJobName=job_name), "TrainingJobStatus")
    if desc["TrainingJobStatus"] != "Completed":
        raise AssertionError(f"setup: linear-learner training job failed: {desc.get('FailureReason')}")
    return desc["ModelArtifacts"]["S3ModelArtifacts"]


def _create_transform_model(ctx, role_arn, model_data_url, *, name_prefix="model") -> str:
    sm = ctx.client("sagemaker")
    model_name = ctx.unique_name(f"sim2real-sm-{name_prefix}-")
    image = _linear_learner_image(ctx.region)

    def _create():
        return sm.create_model(
            ModelName=model_name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={"Image": image, "ModelDataUrl": model_data_url},
            Tags=[{"Key": "sim2real", "Value": "batch-transform-reads-s3-input"}],
        )

    _retry_role_not_ready(_create)
    ctx.on_cleanup(lambda: _delete_model_and_confirm_gone(sm, model_name))
    return model_name


def _delete_model_and_confirm_gone(sm, model_name: str) -> None:
    sm.delete_model(ModelName=model_name)
    try:
        sm.describe_model(ModelName=model_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ValidationException", "ResourceNotFound"):
            raise AssertionError(
                f"expected a not-found-style error describing deleted model {model_name}, got "
                f"{exc.response['Error']['Code']}"
            ) from exc
        message = exc.response["Error"].get("Message")
        if exc.response["Error"]["Code"] == "ValidationException":
            assert message == f'Could not find model "{model_name}".', (
                f"expected DescribeModel of deleted model {model_name} to say it could not be "
                f"found, got {message!r}"
            )
    else:
        raise AssertionError(f"DescribeModel still returned a model after DeleteModel({model_name})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
