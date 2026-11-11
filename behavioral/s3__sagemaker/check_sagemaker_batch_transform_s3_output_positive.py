"""sagemaker-batch-transform-s3-output-positive."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sagemaker-batch-transform-s3-output-positive"
GROUP = "transform-io"
SERVICES = ["s3", "sagemaker"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A batch transform job writes exactly one inference-result object per S3 input
    object, at the S3 key derived from TransformOutput.S3OutputPath, with no strays."""
    xgb_image = _resolve_xgboost_image(ctx)
    bucket = _create_bucket(ctx)
    role_arn = _create_execution_role(ctx, bucket)
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")

    train_csv = "0,1.0,2.0\n1,5.0,6.0\n0,1.2,2.1\n1,4.8,5.9\n0,0.9,1.8\n1,5.2,6.1\n"
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=train_csv.encode())

    train_job = _run_training_job(
        ctx,
        sm,
        role_arn=role_arn,
        image_uri=xgb_image,
        train_s3_uri=f"s3://{bucket}/train/",
        output_s3_uri=f"s3://{bucket}/train-output/",
        hyperparameters={"objective": "binary:logistic", "num_round": "5"},
    )
    final_train = _wait_training_job(sm, train_job)
    assert final_train["TrainingJobStatus"] == "Completed", final_train.get("FailureReason")
    model_data_url = final_train["ModelArtifacts"]["S3ModelArtifacts"]

    model_name = _create_model(ctx, sm, role_arn=role_arn, image_uri=xgb_image, model_data_url=model_data_url)

    # Two separate input objects should each produce their own output object at the
    # configured S3OutputPath destination.
    s3.put_object(Bucket=bucket, Key="transform-in/recordsA.csv", Body=b"1.0,2.0\n")
    s3.put_object(Bucket=bucket, Key="transform-in/recordsB.csv", Body=b"5.0,6.0\n")

    transform_job = _run_transform_job(
        ctx,
        sm,
        model_name=model_name,
        input_s3_uri=f"s3://{bucket}/transform-in/",
        output_s3_uri=f"s3://{bucket}/transform-out/",
    )
    final_xform = _wait_transform_job(sm, transform_job)
    assert final_xform["TransformJobStatus"] == "Completed", final_xform.get("FailureReason")

    out_a = s3.get_object(Bucket=bucket, Key="transform-out/recordsA.csv.out")["Body"].read().decode().strip()
    out_b = s3.get_object(Bucket=bucket, Key="transform-out/recordsB.csv.out")["Body"].read().decode().strip()
    assert len(out_a.splitlines()) == 1, f"expected exactly one output line for recordsA, got {out_a!r}"
    assert len(out_b.splitlines()) == 1, f"expected exactly one output line for recordsB, got {out_b!r}"
    assert 0.0 <= float(out_a) <= 1.0, f"expected recordsA prediction in [0.0, 1.0], got {out_a!r}"
    assert 0.0 <= float(out_b) <= 1.0, f"expected recordsB prediction in [0.0, 1.0], got {out_b!r}"

    listing = s3.list_objects_v2(Bucket=bucket, Prefix="transform-out/")
    keys = {o["Key"] for o in listing.get("Contents", [])}
    assert keys == {"transform-out/recordsA.csv.out", "transform-out/recordsB.csv.out"}, keys


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        objs = [{"Key": o["Key"]} for o in s3.list_objects_v2(Bucket=name).get("Contents", [])]
        for i in range(0, len(objs), 1000):
            batch = objs[i : i + 1000]
            if batch:
                s3.delete_objects(Bucket=name, Delete={"Objects": batch})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_execution_role(ctx, bucket, *, allow_get=True, allow_put=True, kms_key_arn=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    s3_actions = ["s3:ListBucket"]
    if allow_get:
        s3_actions.append("s3:GetObject")
    if allow_put:
        s3_actions.append("s3:PutObject")
    statements = [
        {
            "Effect": "Allow",
            "Action": s3_actions,
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        },
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
            "Resource": "arn:aws:logs:*:*:*",
        },
    ]
    if kms_key_arn:
        statements.append(
            {
                "Effect": "Allow",
                "Action": ["kms:Decrypt", "kms:GenerateDataKey", "kms:DescribeKey"],
                "Resource": kms_key_arn,
            }
        )
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _retry_role_propagation(fn, *, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ValidationException", "AccessDeniedException"):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _poll_until(probe, predicate, *, timeout_s, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last}")


_FRAMEWORK_ECR_ACCOUNT_BY_REGION = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "eu-west-1": "141502667606",
    "eu-west-2": "764974769150",
    "eu-central-1": "492215442770",
    "eu-north-1": "662702820516",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-northeast-1": "354813040037",
    "ap-northeast-2": "366743142698",
    "ap-south-1": "720646828776",
    "ca-central-1": "341280168497",
    "sa-east-1": "737474898029",
}


def _resolve_xgboost_image(ctx):
    # AWS-owned "sagemaker-xgboost" framework container registry paths are publicly
    # documented (see AWS docs "Use XGBoost as a built-in algorithm", tag "1.7-1").
    account = _FRAMEWORK_ECR_ACCOUNT_BY_REGION.get(ctx.region)
    if not account:
        raise AssertionError(f"no known AWS-owned XGBoost container account ID for region {ctx.region}")
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-xgboost:1.7-1"


def _run_training_job(ctx, sm, *, role_arn, image_uri, train_s3_uri, output_s3_uri, hyperparameters):
    name = ctx.unique_name("sim2real-sm-train-")

    def _create():
        sm.create_training_job(
            TrainingJobName=name,
            RoleArn=role_arn,
            AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
            HyperParameters=hyperparameters,
            InputDataConfig=[
                {
                    "ChannelName": "train",
                    "ContentType": "text/csv",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": train_s3_uri,
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                }
            ],
            OutputDataConfig={"S3OutputPath": output_s3_uri},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
            StoppingCondition={"MaxRuntimeInSeconds": 900},
        )

    _retry_role_propagation(_create)
    ctx.on_cleanup(lambda: _stop_training_job(sm, name))
    return name


def _stop_training_job(sm, name):
    """Stop the training job if it still runs; a job that is gone or already finished needs nothing."""
    from botocore.exceptions import ClientError

    try:
        status = sm.describe_training_job(TrainingJobName=name)["TrainingJobStatus"]
    except ClientError as err:
        if not _job_not_found(err):
            raise
        return
    if status != "InProgress":
        return
    try:
        sm.stop_training_job(TrainingJobName=name)
    except ClientError:
        # A job that finished between the describe and the stop is refused; that is not a failure.
        if sm.describe_training_job(TrainingJobName=name)["TrainingJobStatus"] == "InProgress":
            raise


def _job_not_found(err) -> bool:
    """SageMaker answers a missing job with ResourceNotFound or ValidationException "Requested resource not found."."""
    error = err.response["Error"]
    return error["Code"] == "ResourceNotFound" or (
        error["Code"] == "ValidationException" and error.get("Message") == "Requested resource not found."
    )


def _wait_training_job(sm, name, *, timeout_s=900.0):
    return _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=name),
        lambda r: r["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=timeout_s,
        interval_s=15.0,
    )


def _create_model(ctx, sm, *, role_arn, image_uri, model_data_url):
    name = ctx.unique_name("sim2real-sm-model-")

    def _create():
        sm.create_model(
            ModelName=name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={"Image": image_uri, "ModelDataUrl": model_data_url},
        )

    _retry_role_propagation(_create)
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=name))
    return name


def _run_transform_job(ctx, sm, *, model_name, input_s3_uri, output_s3_uri):
    name = ctx.unique_name("sim2real-sm-xform-")
    sm.create_transform_job(
        TransformJobName=name,
        ModelName=model_name,
        TransformInput={
            "DataSource": {"S3DataSource": {"S3DataType": "S3Prefix", "S3Uri": input_s3_uri}},
            "ContentType": "text/csv",
            "SplitType": "Line",
        },
        TransformOutput={"S3OutputPath": output_s3_uri, "Accept": "text/csv", "AssembleWith": "Line"},
        TransformResources={"InstanceType": "ml.m5.large", "InstanceCount": 1},
    )
    ctx.on_cleanup(lambda: _stop_transform_job(sm, name))
    return name


def _stop_transform_job(sm, name):
    """Stop the transform job if it still runs; a job that is gone or already finished needs nothing."""
    from botocore.exceptions import ClientError

    try:
        status = sm.describe_transform_job(TransformJobName=name)["TransformJobStatus"]
    except ClientError as err:
        if not _job_not_found(err):
            raise
        return
    if status != "InProgress":
        return
    try:
        sm.stop_transform_job(TransformJobName=name)
    except ClientError:
        # A job that finished between the describe and the stop is refused; that is not a failure.
        if sm.describe_transform_job(TransformJobName=name)["TransformJobStatus"] == "InProgress":
            raise


def _wait_transform_job(sm, name, *, timeout_s=900.0):
    return _poll_until(
        lambda: sm.describe_transform_job(TransformJobName=name),
        lambda r: r["TransformJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=timeout_s,
        interval_s=15.0,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
