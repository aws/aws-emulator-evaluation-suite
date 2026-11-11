"""model-endpoint-config-update-flow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-endpoint-config-update-flow"
GROUP = "e2e"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An InService endpoint updated to a second EndpointConfig passes through Updating back to
    InService and DescribeEndpoint reports the new config name and variant; after DeleteEndpoint,
    DescribeEndpoint is refused with ValidationException 'Could not find endpoint "<name>".'."""
    image_uri = _xgboost_image_uri(ctx)
    bucket = _create_bucket(ctx)
    role_arn = _create_sagemaker_role(ctx, bucket)
    model_artifact = _train_tiny_xgboost_model(ctx, image_uri, bucket, role_arn)

    sm = ctx.client("sagemaker")
    model_name = ctx.unique_name("sagemaker-sim2real-model-")
    ctx.on_cleanup(lambda: _absent_ok(lambda: sm.delete_model(ModelName=model_name)))
    sm.create_model(
        ModelName=model_name,
        PrimaryContainer={"Image": image_uri, "ModelDataUrl": model_artifact},
        ExecutionRoleArn=role_arn,
    )

    config_name_1 = ctx.unique_name("sagemaker-sim2real-epc1-")
    ctx.on_cleanup(
        lambda: _absent_ok(lambda: sm.delete_endpoint_config(EndpointConfigName=config_name_1))
    )
    sm.create_endpoint_config(
        EndpointConfigName=config_name_1,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "InstanceType": "ml.m5.large",
                "InitialInstanceCount": 1,
            }
        ],
    )

    config_name_2 = ctx.unique_name("sagemaker-sim2real-epc2-")
    ctx.on_cleanup(
        lambda: _absent_ok(lambda: sm.delete_endpoint_config(EndpointConfigName=config_name_2))
    )
    sm.create_endpoint_config(
        EndpointConfigName=config_name_2,
        ProductionVariants=[
            {
                "VariantName": "AllTrafficV2",
                "ModelName": model_name,
                "InstanceType": "ml.m5.large",
                "InitialInstanceCount": 1,
            }
        ],
    )

    endpoint_name = ctx.unique_name("sagemaker-sim2real-ep-")
    ctx.on_cleanup(lambda: _best_effort_delete_endpoint(ctx, endpoint_name))
    sm.create_endpoint(EndpointName=endpoint_name, EndpointConfigName=config_name_1)

    initial = _poll_until_terminal(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        status_key="EndpointStatus",
        terminal={"InService", "Failed"},
        timeout_s=1200,
        interval_s=15,
    )
    assert initial["EndpointStatus"] == "InService", (
        f"expected the initial endpoint to reach InService, got {initial['EndpointStatus']} "
        f"({initial.get('FailureReason')})"
    )
    assert initial["EndpointConfigName"] == config_name_1, (
        f"expected the initial endpoint to report EndpointConfigName={config_name_1!r}, "
        f"got {initial['EndpointConfigName']!r}"
    )

    # Break exactly one thing about the running endpoint: swap it to the second config.
    sm.update_endpoint(EndpointName=endpoint_name, EndpointConfigName=config_name_2)

    # Immediately after the call the endpoint must be mid-transition, not already settled.
    right_after = sm.describe_endpoint(EndpointName=endpoint_name)
    assert right_after["EndpointStatus"] in ("Updating", "SystemUpdating"), (
        f"expected the endpoint to be mid-transition (Updating/SystemUpdating) immediately "
        f"after UpdateEndpoint, got {right_after['EndpointStatus']!r}"
    )

    final = _poll_until_terminal(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        status_key="EndpointStatus",
        terminal={"InService", "Failed", "UpdateRollbackFailed"},
        timeout_s=1200,
        interval_s=15,
    )
    assert final["EndpointStatus"] == "InService", (
        f"expected the endpoint update to land InService, got {final['EndpointStatus']} "
        f"({final.get('FailureReason')})"
    )
    # The consequence of UpdateEndpoint: DescribeEndpoint names the *new* config and
    # serves the new variant, not the one it was created with.
    assert final["EndpointConfigName"] == config_name_2, (
        f"expected the updated endpoint to report EndpointConfigName={config_name_2!r}, "
        f"got {final['EndpointConfigName']!r}"
    )
    variant_names = {v["VariantName"] for v in final["ProductionVariants"]}
    assert variant_names == {"AllTrafficV2"}, (
        f"expected the updated endpoint to serve variant {{'AllTrafficV2'}}, got {variant_names!r}"
    )

    sm.delete_endpoint(EndpointName=endpoint_name)
    gone_code, gone_message = _describe_refusal(sm, endpoint_name, timeout_s=300, interval_s=2)
    assert gone_code == "ValidationException", f"expected ValidationException, got {gone_code!r}"
    expected = f'Could not find endpoint "{endpoint_name}".'
    assert gone_message == expected, f"expected {expected!r}, got {gone_message!r}"


# Built-in "xgboost" algorithm ECR registry account id per region, as the SageMaker SDK's
# image_uri_config/xgboost.json publishes them for version "1". The repo is named plainly
# "xgboost" with a bare major-version tag; the newer "sagemaker-xgboost:<version>-<build>"
# *framework* container lives under a different set of registry accounts.
_XGBOOST_REGISTRY_ACCOUNTS = {
    "us-east-1": "811284229777",
    "us-east-2": "825641698319",
    "us-west-1": "632365934929",
    "us-west-2": "433757028032",
    "af-south-1": "455444449433",
    "ap-east-1": "286214385809",
    "ap-northeast-1": "501404015308",
    "ap-northeast-2": "306986355934",
    "ap-northeast-3": "867004704886",
    "ap-south-1": "991648021394",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "544295431143",
    "ca-central-1": "469771592824",
    "eu-central-1": "813361260812",
    "eu-north-1": "669576153137",
    "eu-west-1": "685385470294",
    "eu-west-2": "644912444149",
    "eu-west-3": "749696950732",
    "me-south-1": "249704162688",
    "sa-east-1": "855470959533",
}


def _xgboost_image_uri(ctx) -> str:
    """The built-in XGBoost algorithm image (bare `xgboost:1` repo) for the region, from the
    per-region registry map so no sagemaker SDK is needed."""
    account = _XGBOOST_REGISTRY_ACCOUNTS.get(ctx.region)
    if account is None:
        raise AssertionError(
            f"no known built-in XGBoost algorithm ECR registry account for region "
            f"{ctx.region!r}; extend _XGBOOST_REGISTRY_ACCOUNTS to close this gap"
        )
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/xgboost:1"


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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


def _describe_refusal(sm, endpoint_name: str, *, timeout_s: float, interval_s: float):
    """Poll DescribeEndpoint until it refuses and return the refusal's (code, message); an endpoint
    that still describes at the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            described = sm.describe_endpoint(EndpointName=endpoint_name)
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"endpoint {endpoint_name} still describes: {described.get('EndpointStatus')}")
        time.sleep(interval_s)


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


def _best_effort_delete_endpoint(ctx, endpoint_name: str) -> None:
    sm = ctx.client("sagemaker")
    _absent_ok(lambda: sm.delete_endpoint(EndpointName=endpoint_name))


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
