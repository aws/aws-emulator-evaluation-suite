"""sagemaker-batch-transform-writes-s3-output."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sagemaker-batch-transform-writes-s3-output"
GROUP = "artifact-output"
SERVICES = ["s3", "sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A completed batch transform job writes one output row per input row to <input-filename>.out under
    TransformOutput.S3OutputPath, and nothing to the input prefix or an unrelated sibling prefix."""
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

    rows = ["0.41,0.51", "0.42,0.52", "0.43,0.53", "0.44,0.54"]
    s3.put_object(Bucket=bucket, Key="transform-input/records.csv", Body=("\n".join(rows) + "\n").encode())

    out_prefix = "nested/predictions/v1/"
    job_name = ctx.unique_name("sim2real-sm-tf-out-")
    sm.create_transform_job(
        TransformJobName=job_name,
        ModelName=model_name,
        TransformInput={
            "DataSource": {"S3DataSource": {"S3DataType": "S3Prefix", "S3Uri": f"s3://{bucket}/transform-input/records.csv"}},
            "ContentType": "text/csv",
            "SplitType": "Line",
        },
        TransformOutput={"S3OutputPath": f"s3://{bucket}/{out_prefix}", "Accept": "text/csv", "AssembleWith": "Line"},
        TransformResources={"InstanceType": "ml.m5.large", "InstanceCount": 1},
        Tags=[{"Key": "sim2real", "Value": "batch-transform-output"}],
    )
    desc = _wait_for_terminal(lambda: sm.describe_transform_job(TransformJobName=job_name), "TransformJobStatus")
    assert desc["TransformJobStatus"] == "Completed", desc.get("FailureReason")

    out_key = f"{out_prefix}records.csv.out"
    head = s3.head_object(Bucket=bucket, Key=out_key)
    assert head["ContentLength"] > 0

    lines = _get_text(ctx, bucket, out_key).strip().splitlines()
    assert len(lines) == len(rows), f"expected {len(rows)} output rows at the configured S3 path, got {len(lines)}"

    # the output must land exactly at the configured destination -- not in the input
    # prefix, and not in an unrelated sibling output prefix.
    assert _list_keys(ctx, bucket, "transform-input/records.csv.out") == []
    assert _list_keys(ctx, bucket, "nested/other/") == []


# AWS-owned ECR accounts hosting the built-in linear-learner algorithm image, one per region --
# not this account's, and not adjustable; a region literal here names AWS's registry, not ours.
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
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "batch-transform-output"}]})

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
        Tags=[{"Key": "sim2real", "Value": "batch-transform-output"}],
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


def _list_keys(ctx, bucket, prefix):
    resp = ctx.client("s3").list_objects_v2(Bucket=bucket, Prefix=prefix)
    return [o["Key"] for o in resp.get("Contents", [])]


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
            Tags=[{"Key": "sim2real", "Value": "batch-transform-output"}],
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
            Tags=[{"Key": "sim2real", "Value": "batch-transform-output"}],
        )

    _retry_role_not_ready(_create)
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))
    return model_name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
