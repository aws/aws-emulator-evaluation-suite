"""endpoint-managed-inservice-transition."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "endpoint-managed-inservice-transition"
GROUP = "server-side"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """After CreateEndpoint, SageMaker autonomously provisions the hosting
    instance(s) and transitions EndpointStatus from Creating to InService,
    serving a real (tiny, freshly-trained) XGBoost model behind the endpoint."""
    image_uri = _xgboost_image_uri(ctx)
    bucket = _create_bucket(ctx)
    role_arn = _create_sagemaker_role(ctx, bucket)
    model_artifact = _train_tiny_xgboost_model(ctx, image_uri, bucket, role_arn)

    sm = ctx.client("sagemaker")
    smr = ctx.client("sagemaker-runtime")
    model_name = ctx.unique_name("sagemaker-sim2real-model-")
    ctx.on_cleanup(lambda: _ignore(lambda: sm.delete_model(ModelName=model_name)))
    sm.create_model(
        ModelName=model_name,
        PrimaryContainer={"Image": image_uri, "ModelDataUrl": model_artifact},
        ExecutionRoleArn=role_arn,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    config_name = ctx.unique_name("sagemaker-sim2real-epc-")
    ctx.on_cleanup(
        lambda: _ignore(lambda: sm.delete_endpoint_config(EndpointConfigName=config_name))
    )
    sm.create_endpoint_config(
        EndpointConfigName=config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "InstanceType": "ml.m5.large",
                "InitialInstanceCount": 1,
            }
        ],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    endpoint_name = ctx.unique_name("sagemaker-sim2real-ep-")
    ctx.on_cleanup(lambda: _best_effort_delete_endpoint(ctx, endpoint_name))
    created = sm.create_endpoint(
        EndpointName=endpoint_name,
        EndpointConfigName=config_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    assert created["EndpointArn"]

    initial = sm.describe_endpoint(EndpointName=endpoint_name)
    assert initial["EndpointStatus"] == "Creating", (
        f"expected a freshly created endpoint to be Creating, got {initial['EndpointStatus']}"
    )

    final = _poll_until_terminal(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        status_key="EndpointStatus",
        terminal={"InService", "Failed"},
        timeout_s=1200,
        interval_s=15,
    )

    assert final["EndpointStatus"] == "InService", (
        f"expected the endpoint to reach InService, got {final['EndpointStatus']} "
        f"({final.get('FailureReason')})"
    )
    assert "CreationTime" in final and "LastModifiedTime" in final

    # The docstring's claim is "serving a real model", not merely "status says InService" --
    # prove it by actually invoking the endpoint and checking the container returns a real
    # binary:logistic probability, not just that the control plane flipped a status word.
    invoked = smr.invoke_endpoint(
        EndpointName=endpoint_name, ContentType="text/csv", Body=b"1.5,1.5"
    )
    prediction = float(invoked["Body"].read().decode().strip())
    assert 0.0 <= prediction <= 1.0, (
        f"expected a binary:logistic probability in [0, 1] from the live container, got {prediction}"
    )

    # Delete the endpoint here so its deletion is a proven negative: describe and invoke must
    # both fail against the deleted endpoint, and the failure must be specific.
    sm.delete_endpoint(EndpointName=endpoint_name)
    gone = _poll_until_client_error(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        timeout_s=600,
        interval_s=10,
    )
    assert gone["Code"] == "ValidationException", (
        f"expected DescribeEndpoint on a deleted endpoint to raise ValidationException, got {gone!r}"
    )
    expected_describe_message = f'Could not find endpoint "{endpoint_name}".'
    assert gone["Message"] == expected_describe_message, (
        f"expected DescribeEndpoint's not-found message {expected_describe_message!r}, "
        f"got {gone['Message']!r}"
    )
    # SageMaker Runtime (the data plane) and SageMaker (the control plane) are different
    # services with different error vocabularies for "no such endpoint": real AWS returns
    # ValidationError from InvokeEndpoint here, not the control plane's ValidationException.
    invoke_after_delete = _poll_until_client_error(
        lambda: smr.invoke_endpoint(EndpointName=endpoint_name, ContentType="text/csv", Body=b"1.5,1.5"),
        timeout_s=180,
        interval_s=10,
    )
    assert invoke_after_delete["Code"] == "ValidationError", (
        f"expected InvokeEndpoint against a deleted endpoint to raise ValidationError, "
        f"got {invoke_after_delete!r}"
    )
    expected_invoke_message = f"Endpoint {endpoint_name} of account {ctx.account} not found."
    assert invoke_after_delete["Message"] == expected_invoke_message, (
        f"expected InvokeEndpoint's not-found message {expected_invoke_message!r}, "
        f"got {invoke_after_delete['Message']!r}"
    )


# ===== helpers =====


# SageMaker XGBoost built-in-algorithm container registry account per region (algorithm mode,
# framework container "sagemaker-xgboost"). Resolved by hand rather than via the 'sagemaker'
# python SDK's image_uris.retrieve, which the runner does not install. Only regions we're
# confident about are listed; an unmapped region is a hard failure, not a guess.
_XGBOOST_REGISTRY_ACCOUNT = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "eu-west-1": "141502667606",
    "eu-central-1": "492215442770",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-northeast-1": "354813040037",
    "ap-south-1": "720646828776",
    "ca-central-1": "341280168497",
    "sa-east-1": "737474898029",
}


def _xgboost_image_uri(ctx) -> str:
    account = _XGBOOST_REGISTRY_ACCOUNT.get(ctx.region)
    if account is None:
        raise AssertionError(
            f"no known XGBoost built-in-algorithm ECR registry account mapped for region {ctx.region}"
        )
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-xgboost:1.7-1"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sagemaker-sim2real-")
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 specifically (it is
    # the implicit default region for the call), so that region is the one legitimate case of
    # branching on ctx.region here rather than always passing a LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")

    def _empty() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])

    _ignore(_empty)
    _ignore(lambda: s3.delete_bucket(Bucket=name))


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
    _ignore(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    _ignore(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
        )
    )
    _ignore(lambda: iam.delete_role(RoleName=role_name))


def _create_training_job_with_role_retry(sm, **kwargs):
    deadline = time.monotonic() + 90
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sm.create_training_job(**kwargs)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            # A fresh role is first not assumable, then its session key is not yet known to S3.
            propagating = "assume" in str(exc).lower() or (
                "The AWS Access Key Id you provided does not exist in our records" in str(exc)
            )
            if code in ("AccessDeniedException", "ValidationException") and propagating:
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


def _train_tiny_xgboost_model(ctx, image_uri: str, bucket: str, role_arn: str) -> str:
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
    key = "train/train.csv"
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(rows).encode("utf-8"))
    train_uri = f"s3://{bucket}/{key}"

    sm = ctx.client("sagemaker")
    job_name = ctx.unique_name("sagemaker-sim2real-train-")
    ctx.on_cleanup(lambda: _best_effort_delete_training_job(ctx, job_name))
    _create_training_job_with_role_retry(
        sm,
        TrainingJobName=job_name,
        RoleArn=role_arn,
        AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
        HyperParameters={"objective": "binary:logistic", "num_round": "5"},
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
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 1800},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    final = _poll_until_terminal(
        lambda: sm.describe_training_job(TrainingJobName=job_name),
        status_key="TrainingJobStatus",
        terminal={"Completed", "Failed", "Stopped"},
        timeout_s=1500,
        interval_s=15,
    )
    if final["TrainingJobStatus"] != "Completed":
        raise AssertionError(
            f"prerequisite training job did not complete: {final['TrainingJobStatus']} "
            f"({final.get('FailureReason')})"
        )
    return final["ModelArtifacts"]["S3ModelArtifacts"]


def _poll_until_terminal(probe, status_key, terminal, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last[status_key] in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"resource never reached a terminal state within {timeout_s}s (last status: "
        f"{last[status_key] if last else 'unknown'})"
    )


def _best_effort_delete_training_job(ctx, job_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
    except ClientError as exc:
        if _is_gone(exc):
            return
        raise
    if status == "InProgress":
        try:
            sm.stop_training_job(TrainingJobName=job_name)
        except ClientError as err:
            # A job no longer InProgress refuses the stop with ValidationException; anything else fails.
            if err.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
                raise
    deadline = time.monotonic() + 300
    while status in ("InProgress", "Stopping"):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"training job {job_name} still {status} 300s after StopTrainingJob")
        time.sleep(2)
        status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
    _ignore(lambda: sm.delete_training_job(TrainingJobName=job_name))


def _poll_until_client_error(probe, timeout_s: float, interval_s: float) -> dict:
    """Call ``probe`` until it raises a ClientError and return that error's ``Error`` dict; a
    call that keeps succeeding past the deadline is an AssertionError, never a falsy result."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            probe()
        except ClientError as exc:
            return exc.response["Error"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"the call kept succeeding for {timeout_s}s; expected a ClientError")
        time.sleep(interval_s)


def _best_effort_delete_endpoint(ctx, endpoint_name: str) -> None:
    sm = ctx.client("sagemaker")
    _ignore(lambda: sm.delete_endpoint(EndpointName=endpoint_name))


def _ignore(fn) -> None:
    """Run a teardown call; return only when the resource is already gone, raise the rest."""
    try:
        fn()
    except ClientError as exc:
        if not _is_gone(exc):
            raise


def _is_gone(exc: ClientError) -> bool:
    """IAM/S3 not-found codes, or SageMaker's ValidationException 'Could not find ...' /
    'Requested resource not found'."""
    error = exc.response["Error"]
    message = error.get("Message", "").lower()
    return error["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket") or (
        error["Code"] == "ValidationException" and ("could not find" in message or "not found" in message)
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
