"""endpoint-lifecycle-creating-to-inservice-to-gone."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "endpoint-lifecycle-creating-to-inservice-to-gone"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A real XGBoost endpoint describes Creating on its first DescribeEndpoint, then InService and serves a non-empty
    inference; after DeleteEndpoint, DescribeEndpoint is refused with ValidationException and the exact not-found
    message.
    """

    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    smr = ctx.client("sagemaker-runtime")
    teardown = {}

    image_uri = _xgboost_image_uri(ctx)

    role_arn = _create_sagemaker_role(ctx)
    bucket = ctx.unique_name("sim2real-sagemaker-").lower().replace("_", "-")
    _create_bucket(ctx, s3, bucket)

    train_csv = "\n".join(
        f"{i % 2},{i},{(i * 3) % 7}" for i in range(60)
    )
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=train_csv.encode())

    training_job_name = ctx.unique_name("sim2real-sm-train-")
    ctx.on_cleanup(lambda: _stop_training_job_if_running(sm, training_job_name, teardown))

    def _start_training():
        return sm.create_training_job(
            TrainingJobName=training_job_name,
            AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
            RoleArn=role_arn,
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
            OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
            StoppingCondition={"MaxRuntimeInSeconds": 900},
            HyperParameters={"objective": "binary:logistic", "num_round": "5"},
            Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
        )

    _retry_role_propagation(_start_training)

    training_desc = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=training_job_name),
        lambda d: d["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert training_desc["TrainingJobStatus"] == "Completed", training_desc.get("FailureReason")
    model_data_url = training_desc["ModelArtifacts"]["S3ModelArtifacts"]

    model_name = ctx.unique_name("sim2real-sm-model-")
    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_model(ModelName=model_name)))
    sm.create_model(
        ModelName=model_name,
        ExecutionRoleArn=role_arn,
        PrimaryContainer={"Image": image_uri, "ModelDataUrl": model_data_url},
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )

    config_name = ctx.unique_name("sim2real-sm-epc-")
    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_endpoint_config(EndpointConfigName=config_name)))
    sm.create_endpoint_config(
        EndpointConfigName=config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "InitialInstanceCount": 1,
                "InstanceType": "ml.m5.large",
                "InitialVariantWeight": 1.0,
            }
        ],
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )

    endpoint_name = ctx.unique_name("sim2real-sm-ep-")
    ctx.on_cleanup(lambda: _delete_endpoint_and_wait(sm, endpoint_name, teardown))
    sm.create_endpoint(
        EndpointName=endpoint_name,
        EndpointConfigName=config_name,
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )

    first = sm.describe_endpoint(EndpointName=endpoint_name)
    assert first["EndpointStatus"] == "Creating", first["EndpointStatus"]

    in_service = _poll_until(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        lambda d: d["EndpointStatus"] in ("InService", "Failed"),
        timeout_s=900.0,
        interval_s=15.0,
    )
    assert in_service["EndpointStatus"] == "InService", in_service.get("FailureReason")

    invoke_resp = smr.invoke_endpoint(
        EndpointName=endpoint_name, ContentType="text/csv", Body=b"1,7"
    )
    payload = invoke_resp["Body"].read().decode().strip()
    assert payload != "", f"expected a non-empty inference payload from the InService endpoint, got {payload!r}"
    float(payload.split(",")[0])  # the XGBoost container returns a numeric score

    sm.delete_endpoint(EndpointName=endpoint_name)

    error = _poll_until_client_error(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name), timeout_s=600.0, interval_s=10.0
    )
    assert error["Code"] == "ValidationException", (
        f"expected DescribeEndpoint to refuse the deleted endpoint with ValidationException, got {error!r}"
    )
    expected_message = f'Could not find endpoint "{endpoint_name}".'
    assert error["Message"] == expected_message, (
        f"expected DescribeEndpoint's not-found message {expected_message!r}, got {error['Message']!r}"
    )


#: SageMaker's built-in XGBoost image lives in a distinct ECR registry account per region. These are
#: the `sagemaker` PyPI SDK's own values (``sagemaker/image_uri_config/xgboost.json``,
#: training+inference; the registry map is identical for versions 1.5-1 and 1.7-1), inlined because
#: the runner has no sagemaker SDK.
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
    account = _XGB_REGISTRY_ACCOUNTS.get(ctx.region)
    if account is None:
        raise AssertionError(
            f"no SageMaker built-in XGBoost ECR registry account mapped for region {ctx.region!r}"
        )
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-xgboost:1.5-1"


def _delete_endpoint_and_wait(sm, endpoint_name, teardown) -> None:
    """Delete the endpoint once it leaves an in-progress state (DeleteEndpoint answers
    ValidationException "Cannot update in-progress endpoint ..." until then), then wait until
    DescribeEndpoint answers "Could not find endpoint ...", every 2 s on the run's teardown
    deadline, 1140 s inside the suite's 1200 s cleanup budget."""
    if "deadline" not in teardown:
        teardown["deadline"] = time.monotonic() + 1140.0
    deadline = teardown["deadline"]
    deleted = False
    while True:
        try:
            if not deleted:
                sm.delete_endpoint(EndpointName=endpoint_name)
                deleted = True
            sm.describe_endpoint(EndpointName=endpoint_name)
        except ClientError as exc:
            err = exc.response["Error"]
            message = err.get("Message", "")
            if err["Code"] != "ValidationException":
                raise
            if message.startswith("Could not find endpoint"):
                return
            if not message.startswith("Cannot update in-progress endpoint"):
                raise
        if time.monotonic() >= deadline:
            raise TimeoutError(f"endpoint {endpoint_name} still present at the teardown deadline")
        time.sleep(2)


def _stop_training_job_if_running(sm, job_name, teardown) -> None:
    """Stop the training job only while it is InProgress (StopTrainingJob refuses a finished job
    with ValidationException "... the training job is in status Completed."), then wait until it
    leaves InProgress/Stopping, on the run's teardown deadline."""
    if "deadline" not in teardown:
        teardown["deadline"] = time.monotonic() + 1140.0
    deadline = teardown["deadline"]
    try:
        status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ValidationException" and err.get("Message") == "Requested resource not found.":
            return
        raise
    if status == "InProgress":
        try:
            sm.stop_training_job(TrainingJobName=job_name)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "ValidationException" or "the training job is in status" not in err.get("Message", ""):
                raise
    while status in ("InProgress", "Stopping"):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"training job {job_name} still {status} at the teardown deadline")
        time.sleep(2)
        status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ValidationException" and err.get("Message", "").startswith("Could not find"):
            return  # SageMaker's not-found answer for an endpoint, config or model
        if err["Code"] not in (
            "NoSuchBucket",
            "NoSuchEntity",
            "NoSuchKey",
            "ResourceNotFound",
        ):
            raise


def _poll_until_client_error(fn, timeout_s: float, interval_s: float) -> dict:
    """Call ``fn`` until it raises a ClientError and return that error's ``Error`` dict; a call
    that keeps succeeding past the deadline is an AssertionError, never a falsy result."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as e:
            return e.response["Error"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"the call kept succeeding for {timeout_s}s; expected a ClientError")
        time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_bucket(ctx, s3, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup() -> None:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                for obj in page.get("Contents", []):
                    _safe(lambda k=obj["Key"]: s3.delete_object(Bucket=bucket, Key=k))
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        _safe(lambda: s3.delete_bucket(Bucket=bucket))

    ctx.on_cleanup(_cleanup)


def _sagemaker_trust_policy() -> str:
    return json.dumps(
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


def _create_sagemaker_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_sagemaker_trust_policy(),
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _safe(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
