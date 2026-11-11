"""sagemaker-batch-transform-missing-role-permission-negative."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "sagemaker-batch-transform-missing-role-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["s3", "sagemaker"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A transform job whose Model execution role can read the model artifact and
    input but lacks s3:PutObject on the output bucket fails to write any output,
    while an identical job using a fully-permissioned role succeeds."""
    xgb_image = _resolve_xgboost_image(ctx)
    bucket = _create_bucket(ctx)
    role_full = _create_execution_role(ctx, bucket, allow_get=True, allow_put=True)
    role_restricted = _create_execution_role(ctx, bucket, allow_get=True, allow_put=False)
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")

    train_csv = "0,1.0,2.0\n1,5.0,6.0\n0,1.2,2.1\n1,4.8,5.9\n0,0.9,1.8\n1,5.2,6.1\n"
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=train_csv.encode())

    train_job = _run_training_job(
        ctx,
        sm,
        role_arn=role_full,
        image_uri=xgb_image,
        train_s3_uri=f"s3://{bucket}/train/",
        output_s3_uri=f"s3://{bucket}/train-output/",
        hyperparameters={"objective": "binary:logistic", "num_round": "5"},
    )
    final_train = _wait_training_job(sm, train_job)
    assert final_train["TrainingJobStatus"] == "Completed", final_train.get("FailureReason")
    model_data_url = final_train["ModelArtifacts"]["S3ModelArtifacts"]

    model_full = _create_model(ctx, sm, role_arn=role_full, image_uri=xgb_image, model_data_url=model_data_url)
    model_restricted = _create_model(
        ctx, sm, role_arn=role_restricted, image_uri=xgb_image, model_data_url=model_data_url
    )

    s3.put_object(Bucket=bucket, Key="transform-in/records.csv", Body=b"1.0,2.0\n5.0,6.0\n")

    # Positive control: role has both GetObject (read model + input) and PutObject
    # (write output) -> job completes and the output object exists.
    xform_ok = _run_transform_job(
        ctx,
        sm,
        model_name=model_full,
        input_s3_uri=f"s3://{bucket}/transform-in/",
        output_s3_uri=f"s3://{bucket}/transform-out-ok/",
    )
    final_ok = _wait_transform_job(sm, xform_ok)
    assert final_ok["TransformJobStatus"] == "Completed", final_ok.get("FailureReason")
    ok_listing = s3.list_objects_v2(Bucket=bucket, Prefix="transform-out-ok/")
    assert ok_listing.get("Contents"), (
        f"the fully-permissioned role has s3:PutObject, so the transform job must write output "
        f"under transform-out-ok/; got {ok_listing.get('Contents')!r}"
    )

    # Break exactly one thing: the Model's execution role can read but not write.
    xform_bad = _run_transform_job(
        ctx,
        sm,
        model_name=model_restricted,
        input_s3_uri=f"s3://{bucket}/transform-in/",
        output_s3_uri=f"s3://{bucket}/transform-out-bad/",
    )
    final_bad = _wait_transform_job(sm, xform_bad)
    assert final_bad["TransformJobStatus"] == "Failed", (
        f"the restricted role can read the model and input but lacks s3:PutObject on the output "
        f"bucket, so the transform job must fail; got status {final_bad['TransformJobStatus']!r}"
    )
    # DescribeTransformJob never names the S3 write denial: AWS wraps it in a generic
    # container-error message. Specificity comes from the twin roles (role_full and
    # role_restricted differ by exactly one permission), not from the message.
    reason = final_bad.get("FailureReason", "").lower()
    assert "clienterror" in reason and "job logs" in reason, (
        f"a batch transform job whose execution role cannot write output fails with SageMaker's "
        f"generic container-error wrapper on DescribeTransformJob; got "
        f"FailureReason={final_bad.get('FailureReason')!r}"
    )
    bad_listing = s3.list_objects_v2(Bucket=bucket, Prefix="transform-out-bad/")
    assert not bad_listing.get("Contents"), (
        f"the restricted role lacks s3:PutObject on the output bucket, so no output object should "
        f"exist under transform-out-bad/; got {bad_listing.get('Contents')!r}"
    )


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
