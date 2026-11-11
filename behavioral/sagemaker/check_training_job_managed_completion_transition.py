"""training-job-managed-completion-transition."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "training-job-managed-completion-transition"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """After CreateTrainingJob, SageMaker autonomously drives the job from InProgress
    to a terminal Completed state (real container run, real instance provisioning)
    without any further client calls beyond polling DescribeTrainingJob."""
    image_uri = _xgboost_image_uri(ctx)
    bucket = _create_bucket(ctx)
    role_arn = _create_sagemaker_role(ctx, bucket)
    train_uri = _upload_training_csv(ctx, bucket, "train/train.csv")

    sm = ctx.client("sagemaker")
    job_name = ctx.unique_name("sagemaker-sim2real-train-")
    ctx.on_cleanup(lambda: _best_effort_delete_training_job(ctx, job_name))

    _create_training_job_with_role_retry(
        sm,
        TrainingJobName=job_name,
        RoleArn=role_arn,
        AlgorithmSpecification={
            "TrainingImage": image_uri,
            "TrainingInputMode": "File",
        },
        HyperParameters={
            "objective": "binary:logistic",
            "num_round": "5",
            "eval_metric": "logloss",
        },
        InputDataConfig=[
            {
                "ChannelName": "train",
                "ContentType": "text/csv",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": train_uri,
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
            }
        ],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
        ResourceConfig={
            "InstanceType": "ml.m5.large",
            "InstanceCount": 1,
            "VolumeSizeInGB": 5,
        },
        StoppingCondition={"MaxRuntimeInSeconds": 1800},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    # The first read is InProgress, or already Completed on a target that runs the job fast.
    described = sm.describe_training_job(TrainingJobName=job_name)
    assert described["TrainingJobStatus"] in ("InProgress", "Completed"), (
        f"expected freshly-created job to read InProgress or Completed, got {described['TrainingJobStatus']}"
    )

    final = _poll_until_terminal(
        lambda: sm.describe_training_job(TrainingJobName=job_name),
        status_key="TrainingJobStatus",
        terminal={"Completed", "Failed", "Stopped"},
        timeout_s=1500,
        interval_s=15,
    )

    assert final["TrainingJobStatus"] == "Completed", (
        f"expected the tiny valid training job to complete, got "
        f"{final['TrainingJobStatus']} ({final.get('FailureReason')})"
    )
    # the service, not the client, populated these timestamps as it drove the job
    assert "TrainingStartTime" in final and "TrainingEndTime" in final, (
        f"expected the server to stamp TrainingStartTime/TrainingEndTime on a completed job, got keys {sorted(final.keys())}"
    )
    assert final["ModelArtifacts"]["S3ModelArtifacts"].startswith(f"s3://{bucket}/"), (
        f"expected the model artifact to land under s3://{bucket}/, got {final['ModelArtifacts']['S3ModelArtifacts']}"
    )


#: SageMaker's built-in XGBoost image lives in a distinct ECR registry account per region. These are
#: the `sagemaker` PyPI SDK's OWN values (sagemaker 2.257.6,
#: ``sagemaker/image_uri_config/xgboost.json``, training+inference, versions 1.5-1 and 1.7-1 -- the
#: registry map is identical across those versions), so this is a transcription of the table
#: ``image_uris.retrieve`` reads, not a guess. It is inlined because pulling that SDK in just to
#: read a static JSON map costs torch + CUDA + mlflow and downgrades protobuf and
#: antlr4-python3-runtime in the runner.
_XGB_REGISTRY_ACCOUNTS = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "ap-northeast-1": "354813040037",
    "ap-northeast-2": "366743142698",
    "ap-south-1": "720646828776",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ca-central-1": "341280168497",
    "eu-central-1": "492215442770",
    "eu-north-1": "662702820516",
    "eu-west-1": "141502667606",
    "eu-west-2": "764974769150",
    "eu-west-3": "659782779980",
    "sa-east-1": "737474898029",
}


def _xgboost_image_uri(ctx) -> str:
    region = ctx.region
    account = _XGB_REGISTRY_ACCOUNTS.get(region)
    if account is None:
        raise AssertionError(
            f"no SageMaker built-in XGBoost ECR registry account mapped for region {region!r} "
            "- add it from the SDK's image_uri_config/xgboost.json to close this gap"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/sagemaker-xgboost:1.7-1"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sagemaker-sim2real-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    for obj in resp.get("Contents", []):
        _absent_ok(lambda key=obj["Key"]: s3.delete_object(Bucket=name, Key=key))
    _absent_ok(lambda: s3.delete_bucket(Bucket=name))


def _upload_training_csv(ctx, bucket: str, key: str) -> str:
    s3 = ctx.client("s3")
    rows = [
        "0,1.0,2.0",
        "1,2.0,1.0",
        "0,1.5,2.5",
        "1,3.0,0.5",
        "0,0.5,3.0",
        "1,2.5,0.2",
        "0,0.8,2.8",
        "1,2.8,0.4",
    ]
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(rows).encode("utf-8"))
    return f"s3://{bucket}/{key}"


def _create_sagemaker_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sagemaker-sim2real-role-")
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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_sagemaker_role(ctx, role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
    )
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(inline_policy)
    )
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _delete_sagemaker_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    _absent_ok(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    _absent_ok(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
        )
    )
    _absent_ok(lambda: iam.delete_role(RoleName=role_name))


def _create_training_job_with_role_retry(sm, **kwargs):
    """New IAM roles can take a few seconds to propagate before SageMaker can
    assume them; retry on AccessDenied for a bounded window rather than sleeping
    a fixed duration."""
    deadline = time.monotonic() + 90
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "ValidationException") and "assume" in str(exc).lower():
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


def _poll_until_terminal(probe, status_key, terminal, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last[status_key] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"job never reached a terminal state within {timeout_s}s (last status: "
        f"{last[status_key] if last else 'unknown'})"
    )


def _best_effort_delete_training_job(ctx, job_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
    except ClientError as err:
        if _is_gone(err):
            return
        raise
    if status in ("InProgress", "Stopping"):
        if status == "InProgress":
            _absent_ok(lambda: sm.stop_training_job(TrainingJobName=job_name))
        deadline = time.monotonic() + 300
        while status in ("InProgress", "Stopping"):
            if time.monotonic() >= deadline:
                raise AssertionError(f"training job {job_name} still {status} after 300s of StopTrainingJob")
            time.sleep(2)
            status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
    _absent_ok(lambda: sm.delete_training_job(TrainingJobName=job_name))


_GONE_CODES = ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket", "NoSuchKey")


def _is_gone(err: ClientError) -> bool:
    """IAM/S3 not-found codes, or SageMaker's ValidationException 'Could not find ...' /
    'Requested resource not found'."""
    error = err.response["Error"]
    message = error.get("Message", "").lower()
    return error["Code"] in _GONE_CODES or (
        error["Code"] == "ValidationException" and ("could not find" in message or "not found" in message)
    )


def _absent_ok(fn) -> None:
    """Teardown call: returns when the resource is already gone and raises any other failure."""
    try:
        fn()
    except ClientError as err:
        if not _is_gone(err):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
