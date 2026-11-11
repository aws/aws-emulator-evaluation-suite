"""e2e-endpoint-create-invoke-scale-teardown."""
from __future__ import annotations

import json
import math
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-endpoint-create-invoke-scale-teardown"
GROUP = "e2e"
SERVICES = ["sagemaker"]

# Built-in "linear-learner" algorithm image account IDs, stable across years, one per
# region. See https://docs.aws.amazon.com/sagemaker/latest/dg/linear-learner.html
_LINEAR_LEARNER_ACCOUNTS = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "eu-west-1": "438346466558",
    "eu-central-1": "664544806723",
    "eu-north-1": "669576153137",
    "eu-west-2": "644912444149",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-south-1": "991648021394",
    "sa-east-1": "855470959533",
    "ca-central-1": "469771592824",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Full lifecycle: train a real model, create model+config+endpoint, observe it
    reach InService, invoke it and get a real inference response, then delete it and
    confirm both DescribeEndpoint and InvokeEndpoint agree the endpoint is truly gone."""
    image_uri = _linear_learner_image(ctx)
    if image_uri is None:
        raise AssertionError(
            f"no known built-in linear-learner registry account mapped for region "
            f"{ctx.region!r}; would need the SageMaker Python SDK's image_uris.retrieve "
            "to resolve this dynamically"
        )

    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_bucket(ctx)
    _upload_training_csv(ctx, bucket)

    job_name = ctx.unique_name("sim2real-sm-train-")
    _create_training_job_retrying_role_propagation(
        sm,
        TrainingJobName=job_name,
        AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
        RoleArn=role_arn,
        InputDataConfig=[
            {
                "ChannelName": "train",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": f"s3://{bucket}/train/",
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
                "ContentType": "text/csv",
            }
        ],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        HyperParameters={
            "feature_dim": "2",
            "predictor_type": "regressor",
            "mini_batch_size": "10",
        },
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_training_job(sm, job_name))

    train_desc = _wait_training_job(sm, job_name, timeout_s=1200)
    assert train_desc["TrainingJobStatus"] == "Completed", train_desc.get("FailureReason")
    model_data_url = train_desc["ModelArtifacts"]["S3ModelArtifacts"]

    model_name = ctx.unique_name("sim2real-sm-model-")
    sm.create_model(
        ModelName=model_name,
        ExecutionRoleArn=role_arn,
        PrimaryContainer={"Image": image_uri, "ModelDataUrl": model_data_url},
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_name))

    config_name = ctx.unique_name("sim2real-sm-epc-")
    sm.create_endpoint_config(
        EndpointConfigName=config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "InitialInstanceCount": 1,
                "InstanceType": "ml.m5.large",
            }
        ],
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint_config(EndpointConfigName=config_name))

    endpoint_name = ctx.unique_name("sim2real-sm-ep-")
    sm.create_endpoint(
        EndpointName=endpoint_name,
        EndpointConfigName=config_name,
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    endpoint_deleted = {"value": False}

    def _delete_endpoint_if_needed() -> None:
        if not endpoint_deleted["value"]:
            from botocore.exceptions import ClientError

            try:
                sm.delete_endpoint(EndpointName=endpoint_name)
            except ClientError as exc:
                error = exc.response["Error"]
                if error["Code"] != "ValidationException" or "Could not find" not in error.get("Message", ""):
                    raise

    ctx.on_cleanup(_delete_endpoint_if_needed)

    desc = _wait_endpoint(sm, endpoint_name, timeout_s=900)
    assert desc["EndpointStatus"] == "InService", desc.get("FailureReason")

    rt = ctx.client("sagemaker-runtime")
    resp = rt.invoke_endpoint(
        EndpointName=endpoint_name,
        ContentType="text/csv",
        Accept="application/json",
        Body=b"5.0,3.0\n",
    )
    payload = json.loads(resp["Body"].read())
    predictions = payload["predictions"]
    assert len(predictions) == 1, f"expected 1 prediction for 1 input row, got {len(predictions)}"
    score = predictions[0]["score"]
    assert isinstance(score, (int, float)), f"expected a numeric score, got {score!r}"
    assert math.isfinite(score), f"expected a finite score, got {score!r}"

    # Teardown: delete the endpoint and confirm it is truly gone, both on the control
    # plane (DescribeEndpoint) and the data plane (InvokeEndpoint).
    sm.delete_endpoint(EndpointName=endpoint_name)
    endpoint_deleted["value"] = True

    code, message = _poll_refusal(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name), timeout_s=120, interval_s=2
    )
    assert code == "ValidationException", code
    expected = f'Could not find endpoint "{endpoint_name}".'
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # The data plane can keep serving for a while after DescribeEndpoint already
    # reports the control plane's deletion, so this is its own bounded poll rather
    # than a single call right after the describe poll settles.
    invoke_code, invoke_message = _poll_refusal(
        lambda: rt.invoke_endpoint(
            EndpointName=endpoint_name,
            ContentType="text/csv",
            Accept="application/json",
            Body=b"5.0,3.0\n",
        ),
        timeout_s=300,
        interval_s=2,
    )
    assert invoke_code == "ValidationError", invoke_code
    account = role_arn.split(":")[4]
    expected = f"Endpoint {endpoint_name} of account {account} not found."
    assert invoke_message == expected, f"expected {expected!r}, got {invoke_message!r}"


# ===== helpers =====

_SAGEMAKER_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


def _linear_learner_image(ctx) -> str | None:
    account = _LINEAR_LEARNER_ACCOUNTS.get(ctx.region)
    if not account:
        return None
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/linear-learner:1"


def _poll_refusal(fn, *, timeout_s: float, interval_s: float):
    """Call fn() until it raises ClientError and return that error's (code, message); a call that
    still succeeds at the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected a refusal within {timeout_s}s, last result {result!r}")
        time.sleep(interval_s)


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SAGEMAKER_TRUST_POLICY,
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["Role"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        from botocore.exceptions import ClientError

        for delete in (
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                delete()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    return role["Arn"]


def _create_training_job_retrying_role_propagation(
    sm, *, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs
) -> None:
    """CreateTrainingJob can reject a freshly-created role before IAM's
    cross-service trust propagates; retry on that specific rejection rather than
    sleeping blind, bounded by timeout_s."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.create_training_job(**kwargs)
            return
        except Exception as exc:
            response = getattr(exc, "response", None)
            if response is None:
                raise
            error = response.get("Error", {})
            message = error.get("Message", "")
            is_role_propagation = error.get("Code") == "ValidationException" and (
                "AssumeRole" in message or "not authorized" in message or "role" in message.lower()
            )
            if not is_role_propagation:
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateTrainingJob still rejects the freshly-created role after "
                    f"{timeout_s}s of retrying (last error: {message!r})"
                ) from exc
            time.sleep(interval_s)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    # AmazonSageMakerFullAccess only grants s3:GetObject/PutObject/DeleteObject on
    # buckets whose name contains "sagemaker" -- a plain "sim2real-sm-" bucket is
    # denied by the role's own attached policy.
    bucket = ctx.unique_name("sim2real-sagemaker-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real-owner", "Value": "behavioral-suite"}]},
    )

    def _cleanup() -> None:
        from botocore.exceptions import ClientError

        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _upload_training_csv(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    lines = []
    for i in range(50):
        x1 = float(i % 10)
        x2 = float((i * 3) % 7)
        label = 3.0 * x1 + 2.0 * x2 + 1.0
        lines.append(f"{label},{x1},{x2}")
    body = ("\n".join(lines) + "\n").encode("utf-8")
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=body)


def _wait_training_job(sm, job_name: str, timeout_s: float = 1200.0) -> dict:
    deadline = time.monotonic() + timeout_s
    desc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        desc = sm.describe_training_job(TrainingJobName=job_name)
        status = desc["TrainingJobStatus"]
        if status in ("Completed", "Failed", "Stopped"):
            return desc
        time.sleep(2)
    raise AssertionError(f"training job {job_name} did not finish within {timeout_s}s: {desc}")


def _safe_delete_training_job(sm, job_name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        desc = sm.describe_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] == "ResourceNotFound" or "not found" in error.get("Message", "").lower():
            return
        raise
    if desc["TrainingJobStatus"] not in ("Completed", "Failed", "Stopped"):
        try:
            sm.stop_training_job(TrainingJobName=job_name)
        except ClientError as err:
            # A job that has left InProgress refuses the stop with ValidationException; anything else fails.
            if err.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
                raise
        _wait_training_job(sm, job_name, timeout_s=300)
    try:
        sm.delete_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _wait_endpoint(sm, endpoint_name: str, timeout_s: float = 900.0) -> dict:
    deadline = time.monotonic() + timeout_s
    desc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        desc = sm.describe_endpoint(EndpointName=endpoint_name)
        status = desc["EndpointStatus"]
        if status in ("InService", "Failed"):
            return desc
        time.sleep(2)
    raise AssertionError(f"endpoint {endpoint_name} did not settle within {timeout_s}s: {desc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
