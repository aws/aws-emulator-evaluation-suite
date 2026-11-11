"""endpoint-lifecycle-config-to-inservice-to-delete."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "endpoint-lifecycle-config-to-inservice-to-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


# SageMaker XGBoost built-in-algorithm container registry account per region (algorithm
# mode, framework container "sagemaker-xgboost"). Only regions we're confident about are
# listed; unknown regions are skipped rather than guessed.
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A serverless Endpoint built from an EndpointConfig over a real training job's model
    reaches InService, and both the endpoint and its config are deletable and then refused
    on describe."""

    xgb_account = _XGBOOST_REGISTRY_ACCOUNT.get(ctx.region)
    if xgb_account is None:
        raise AssertionError(
            f"no known XGBoost built-in-algorithm ECR registry account mapped for region {ctx.region}"
        )
    xgb_image = f"{xgb_account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-xgboost:1.7-1"

    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_training_bucket(ctx)

    job_name = ctx.unique_name("sim2real-train-")

    def _start_training():
        return sm.create_training_job(
            TrainingJobName=job_name,
            RoleArn=role_arn,
            AlgorithmSpecification={"TrainingImage": xgb_image, "TrainingInputMode": "File"},
            HyperParameters={"objective": "reg:squarederror", "num_round": "2"},
            InputDataConfig=[
                {
                    "ChannelName": "train",
                    "ContentType": "text/csv",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": f"s3://{bucket}/train/",
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                }
            ],
            OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output"},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
            StoppingCondition={"MaxRuntimeInSeconds": 600},
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    _retry_role_propagation(_start_training)
    ctx.on_cleanup(lambda: _stop_training_job_ignore(sm, job_name))

    training_desc = _poll_until(
        probe=lambda: sm.describe_training_job(TrainingJobName=job_name),
        predicate=lambda d: d["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900,
        interval_s=15,
    )
    assert training_desc["TrainingJobStatus"] == "Completed", (
        f"expected training job {job_name} to reach Completed, "
        f"got {training_desc['TrainingJobStatus']} ({training_desc.get('FailureReason')})"
    )
    model_data_url = training_desc["ModelArtifacts"]["S3ModelArtifacts"]

    model_name = ctx.unique_name("sim2real-model-")
    sm.create_model(
        ModelName=model_name,
        PrimaryContainer={"Image": xgb_image, "ModelDataUrl": model_data_url},
        ExecutionRoleArn=role_arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_model_ignore(sm, model_name))

    config_name = ctx.unique_name("sim2real-epconfig-")
    sm.create_endpoint_config(
        EndpointConfigName=config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "ServerlessConfig": {"MemorySizeInMB": 2048, "MaxConcurrency": 1},
            }
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_endpoint_config_ignore(sm, config_name))

    endpoint_name = ctx.unique_name("sim2real-endpoint-")
    sm.create_endpoint(
        EndpointName=endpoint_name,
        EndpointConfigName=config_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_endpoint_ignore(sm, endpoint_name))

    endpoint_desc = _poll_until(
        probe=lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        predicate=lambda d: d["EndpointStatus"] in ("InService", "Failed"),
        timeout_s=900,
        interval_s=15,
    )
    assert endpoint_desc["EndpointStatus"] == "InService", (
        f"expected endpoint {endpoint_name} to reach InService, "
        f"got {endpoint_desc['EndpointStatus']} ({endpoint_desc.get('FailureReason')})"
    )
    assert endpoint_desc["EndpointConfigName"] == config_name, (
        f"expected DescribeEndpoint to report EndpointConfigName={config_name!r}, "
        f"got {endpoint_desc['EndpointConfigName']!r}"
    )

    sm.delete_endpoint(EndpointName=endpoint_name)
    # DeleteEndpoint is asynchronous: DescribeEndpoint keeps answering (typically with
    # EndpointStatus="Deleting") for a stretch after the call returns, confirmed on real AWS --
    # an immediate single describe still found the endpoint and this assert failed with code=None.
    code, message = _refusal_eventually(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name), timeout_s=120, interval_s=5
    )
    assert code == "ValidationException", (
        f"expected DescribeEndpoint on deleted endpoint {endpoint_name} to eventually fail with "
        f"ValidationException within 120s, got {code!r}"
    )
    expected = f'Could not find endpoint "{endpoint_name}".'
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    sm.delete_endpoint_config(EndpointConfigName=config_name)
    config_code, config_message = _error(lambda: sm.describe_endpoint_config(EndpointConfigName=config_name))
    assert config_code == "ValidationException", (
        f"expected DescribeEndpointConfig on deleted config {config_name} to fail with "
        f"ValidationException, got {config_code!r}"
    )
    expected = f'Could not find endpoint configuration "{config_name}".'
    assert config_message == expected, f"expected message {expected!r}, got {config_message!r}"


# ===== helpers =====
def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() > deadline:
            return last
        time.sleep(interval_s)
        last = probe()
    return last


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        e = err.response["Error"]
        return e["Code"], e.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _refusal_eventually(fn, *, timeout_s, interval_s):
    """Poll fn() until it is refused; return the refusal's (code, message). A call that still
    SUCCEEDS at the deadline raises: the deleted resource must stop being describable."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as err:
            e = err.response["Error"]
            return e["Code"], e.get("Message")
        time.sleep(interval_s)
    raise AssertionError(
        f"expected the call to be rejected within {timeout_s}s, but it still SUCCEEDED and "
        f"returned {result!r}"
    )


def _retry_role_propagation(fn, timeout_s: float = 120.0, interval_s: float = 5.0):
    """A freshly created IAM role is eventually consistent: CreateTrainingJob can reject it
    with ValidationException mentioning the role before SageMaker's own view of IAM catches
    up. Retry only that specific, named condition -- never a bare sleep -- and re-raise
    anything else immediately."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_exc = err
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-exec-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    for policy_arn in (
        "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    ):
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: _detach_policy_ignore(iam, role_name, p))
    ctx.on_cleanup(lambda: _delete_role_ignore(iam, role_name))
    return role_arn


def _create_training_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sm-train-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket_ignore(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    rows = []
    for i in range(30):
        label = float(i % 5)
        rows.append(f"{label},{i},{i * 2},{i % 3}")
    csv_body = "\n".join(rows).encode("utf-8")
    s3.put_object(Bucket=bucket, Key="train/data.csv", Body=csv_body)
    return bucket


def _stop_training_job_ignore(sm, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.stop_training_job(TrainingJobName=name)
    except ClientError as exc:
        # A job that is not InProgress refuses the stop with ValidationException; anything else fails.
        if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=name)["TrainingJobStatus"] == "InProgress":
            raise


def _ignore_gone(fn, retry_s: float = 0.0) -> None:
    """Run a teardown delete; return only when the resource is already gone, retry any other
    ValidationException every 2 s for retry_s, raise the rest."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + retry_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] in ("NoSuchEntity", "NoSuchBucket"):
                return
            if error["Code"] != "ValidationException":
                raise
            if "Could not find" in error.get("Message", ""):
                return
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_model_ignore(sm, name: str) -> None:
    _ignore_gone(lambda: sm.delete_model(ModelName=name))


def _delete_endpoint_ignore(sm, name: str) -> None:
    # A still-Creating endpoint refuses the delete with ValidationException: retried for 600 s.
    _ignore_gone(lambda: sm.delete_endpoint(EndpointName=name), retry_s=600.0)


def _delete_endpoint_config_ignore(sm, name: str) -> None:
    _ignore_gone(lambda: sm.delete_endpoint_config(EndpointConfigName=name))


def _delete_bucket_ignore(s3, bucket: str) -> None:
    def _empty_and_delete() -> None:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    _ignore_gone(_empty_and_delete)


def _detach_policy_ignore(iam, role_name: str, policy_arn: str) -> None:
    _ignore_gone(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))


def _delete_role_ignore(iam, role_name: str) -> None:
    _ignore_gone(lambda: iam.delete_role(RoleName=role_name))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
