"""e2e-training-to-endpoint-inference-flow."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-training-to-endpoint-inference-flow"
GROUP = "e2e"
SERVICES = ["sagemaker"]

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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A tiny XGBoost training job completes and its artifact serves from an InService endpoint whose AllTraffic variant
    resolves to the model with the job's own ModelDataUrl; after DeleteEndpoint, DescribeEndpoint is refused with
    ValidationException 'Could not find endpoint "<name>".'.
    """
    account = _XGBOOST_REGISTRY_ACCOUNTS.get(ctx.region)
    if account is None:
        raise AssertionError(
            f"no known built-in XGBoost algorithm ECR registry account for region "
            f"{ctx.region!r}; extend _XGBOOST_REGISTRY_ACCOUNTS to close this gap"
        )
    image_uri = f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/xgboost:1"

    sm = ctx.client("sagemaker")
    role_arn = _create_execution_role(ctx)
    bucket = _create_bucket(ctx)

    train_key = "train/train.csv"
    ctx.client("s3").put_object(Bucket=bucket, Key=train_key, Body=_training_csv().encode())

    job_name = ctx.unique_name("sim2real-sm-train-")
    _create_training_job_with_role_propagation_retry(
        sm,
        TrainingJobName=job_name,
        RoleArn=role_arn,
        AlgorithmSpecification={"TrainingImage": image_uri, "TrainingInputMode": "File"},
        InputDataConfig=[
            {
                "ChannelName": "train",
                "ContentType": "text/csv",
                "CompressionType": "None",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": f"s3://{bucket}/{train_key}",
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
            }
        ],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 1800},
        HyperParameters={"objective": "binary:logistic", "num_round": "10"},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(sm.delete_training_job, TrainingJobName=job_name))

    train_desc = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=job_name),
        lambda d: d["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=1200,
        interval_s=20,
    )
    assert train_desc["TrainingJobStatus"] == "Completed", train_desc.get("FailureReason")
    model_artifacts = train_desc["ModelArtifacts"]["S3ModelArtifacts"]

    model_name = ctx.unique_name("sim2real-sm-model-")
    sm.create_model(
        ModelName=model_name,
        PrimaryContainer={"Image": image_uri, "ModelDataUrl": model_artifacts},
        ExecutionRoleArn=role_arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(sm.delete_model, ModelName=model_name))

    config_name = ctx.unique_name("sim2real-sm-epc-")
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(sm.delete_endpoint_config, EndpointConfigName=config_name))

    endpoint_name = ctx.unique_name("sim2real-sm-ep-")
    sm.create_endpoint(
        EndpointName=endpoint_name,
        EndpointConfigName=config_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(sm.delete_endpoint, EndpointName=endpoint_name))

    ep_desc = _poll_until(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        lambda d: d["EndpointStatus"] in ("InService", "Failed"),
        timeout_s=1200,
        interval_s=15,
    )
    assert ep_desc["EndpointStatus"] == "InService", ep_desc.get("FailureReason")
    assert ep_desc["ProductionVariants"][0]["VariantName"] == "AllTraffic", (
        f"expected variant 'AllTraffic', got {ep_desc['ProductionVariants'][0]['VariantName']!r}"
    )

    # Cross-check the whole chain: endpoint -> its active config -> the model it
    # deploys -> the S3 model artifact produced by the training job above.
    cfg_desc = sm.describe_endpoint_config(EndpointConfigName=config_name)
    variant_model_name = cfg_desc["ProductionVariants"][0]["ModelName"]
    assert variant_model_name == model_name, (
        f"endpoint config {config_name} variant references model {variant_model_name!r}, "
        f"expected the model this check created ({model_name!r})"
    )
    model_desc = sm.describe_model(ModelName=variant_model_name)
    assert model_desc["PrimaryContainer"]["ModelDataUrl"] == model_artifacts, (
        f"model {variant_model_name} references artifact "
        f"{model_desc['PrimaryContainer']['ModelDataUrl']!r}, expected the training job's own "
        f"artifact ({model_artifacts!r})"
    )

    # The endpoint this check created is deleted here (not only in cleanup) so the
    # delete's effect can be asserted: an independent read must report it gone.
    sm.delete_endpoint(EndpointName=endpoint_name)
    delete_code, delete_message = _refusal_eventually(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name), timeout_s=120, interval_s=5
    )
    assert delete_code == "ValidationException", (
        f"expected ValidationException reading a deleted endpoint, got {delete_code!r}"
    )
    expected = f'Could not find endpoint "{endpoint_name}".'
    assert delete_message == expected, f"expected message {expected!r}, got {delete_message!r}"


def _safe(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> None:
    try:
        fn(*args, **kwargs)
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "ValidationException" and err.get("Message", "").startswith("Could not find"):
            return  # SageMaker's not-found answer for an endpoint, config or model
        if err["Code"] not in (
            "NoSuchBucket",
            "NoSuchEntity",
            "ResourceNotFound",
        ):
            raise


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


def _create_training_job_with_role_propagation_retry(sm, **kwargs: Any) -> None:
    # IAM role/policy propagation to SageMaker's assume-role check is eventually
    # consistent; a fresh execution role can be reported by GetRole yet still be
    # refused here for a short window. Retry the actual operation that needs the
    # role to be ready, bounded, rather than guessing how long propagation takes.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 120
    while True:
        try:
            sm.create_training_job(**kwargs)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _training_csv() -> str:
    lines = []
    seed = 12345
    for i in range(60):
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        f1 = (seed % 2000 - 1000) / 100.0
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        f2 = (seed % 2000 - 1000) / 100.0
        seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF
        f3 = (seed % 2000 - 1000) / 100.0
        label = 1 if (f1 + f2 + f3) > 0 else 0
        lines.append(f"{label},{f1:.3f},{f2:.3f},{f3:.3f}")
    return "\n".join(lines) + "\n"


def _create_execution_role(ctx) -> str:
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        _safe(iam.detach_role_policy, RoleName=role_name, PolicyArn=policy_arn)
        _safe(iam.delete_role, RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    # IAM role/policy attachment propagation is eventually consistent; see
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    # The actual wait for that propagation happens as a bounded retry around the
    # first operation that needs SageMaker to assume this role (see
    # _create_training_job_with_role_propagation_retry), not as a blind sleep here.
    _poll_until(lambda: iam.get_role(RoleName=role_name), lambda r: bool(r["Role"]["Arn"]), timeout_s=30, interval_s=2)
    return role_arn


def _create_bucket(ctx) -> str:
    # AmazonSageMakerFullAccess only grants S3 object read/write on buckets whose
    # name contains "sagemaker" -- the bucket name must reflect that or the
    # execution role can't actually read/write training data or model artifacts.
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sagemaker-bucket-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup() -> None:
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
        _safe(s3.delete_bucket, Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
