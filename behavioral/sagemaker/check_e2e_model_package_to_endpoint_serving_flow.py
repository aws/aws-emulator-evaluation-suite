"""e2e-model-package-to-endpoint-serving-flow."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-model-package-to-endpoint-serving-flow"
GROUP = "e2e"
SERVICES = ["sagemaker"]

# Account IDs that own the SageMaker XGBoost framework image ("sagemaker-xgboost:<version>"),
# by region. The built-in-algorithm registry account (repo "xgboost") has no "sagemaker-xgboost"
# repo, and that wrong pairing surfaces as a cross-account ECR AccessDenied.
_XGBOOST_REGISTRY_ACCOUNT = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "af-south-1": "510948584623",
    "ap-east-1": "651117190479",
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
    "me-south-1": "801668240914",
    "sa-east-1": "737474898029",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A model package registered from a real trained artifact, wrapped into a
    Model, deployed via an EndpointConfig, actually reaches InService and serves
    inference -- and full teardown leaves no orphaned Model/ModelPackage/Endpoint."""
    account = _XGBOOST_REGISTRY_ACCOUNT.get(ctx.region)
    if account is None:
        raise AssertionError(f"no known built-in XGBoost algorithm image account for region {ctx.region}")
    training_image = f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-xgboost:1.7-1"

    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    # --- S3 bucket for training data/output ("sagemaker" in the name so that
    # AmazonSageMakerFullAccess's bucket-name-scoped S3 permissions apply) ---
    bucket = ctx.unique_name("sagemaker-sim2real-mp-").lower()
    _create_bucket(s3, bucket, ctx.region)
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    rows = []
    for i in range(40):
        label = i % 2
        f1 = float(i) + (0.15 if label else -0.15)
        f2 = float(i) * 0.5
        rows.append(f"{label},{f1:.3f},{f2:.3f}")
    csv_body = "\n".join(rows) + "\n"
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=csv_body.encode("utf-8"))

    # --- Execution role usable by both the training job and the hosted endpoint ---
    role_name = ctx.unique_name("sim2real-sm-mp-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")

    # --- Train a tiny, real XGBoost model ---
    training_job_name = ctx.unique_name("sim2real-mp-train-")
    _create_training_job_with_retry(
        sm,
        TrainingJobName=training_job_name,
        AlgorithmSpecification={"TrainingImage": training_image, "TrainingInputMode": "File"},
        RoleArn=role_arn,
        HyperParameters={"objective": "binary:logistic", "num_round": "5", "max_depth": "2"},
        InputDataConfig=[
            {
                "ChannelName": "train",
                "ContentType": "text/csv",
                "CompressionType": "None",
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    train_status = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=training_job_name)["TrainingJobStatus"],
        lambda s: s in ("Completed", "Failed", "Stopped"),
        timeout_s=1200,
        interval_s=15,
    )
    described = sm.describe_training_job(TrainingJobName=training_job_name)
    assert train_status == "Completed", f"training job did not complete: {described.get('FailureReason')}"
    model_data_url = described["ModelArtifacts"]["S3ModelArtifacts"]

    # --- Register the trained artifact as a ModelPackage ---
    model_package_name = ctx.unique_name("sim2real-mp-")
    mp_arn = sm.create_model_package(
        ModelPackageName=model_package_name,
        ModelApprovalStatus="Approved",
        InferenceSpecification={
            "Containers": [{"Image": training_image, "ModelDataUrl": model_data_url}],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
            "SupportedRealtimeInferenceInstanceTypes": ["ml.m5.large"],
            "SupportedTransformInstanceTypes": ["ml.m5.large"],
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["ModelPackageArn"]
    ctx.on_cleanup(lambda: _delete_model_package(sm, mp_arn))

    # ModelPackage registration validates the container asynchronously: it starts
    # "Pending" and CreateModel rejects anything but "Completed".
    mp_status = _poll_until(
        lambda: sm.describe_model_package(ModelPackageName=mp_arn)["ModelPackageStatus"],
        lambda s: s in ("Completed", "Failed"),
        timeout_s=300,
        interval_s=10,
    )
    mp_described = sm.describe_model_package(ModelPackageName=mp_arn)
    assert mp_status == "Completed", (
        f"model package validation did not complete: {mp_described.get('ModelPackageStatusDetails')}"
    )

    # --- Wrap the ModelPackage into a Model ---
    model_name = ctx.unique_name("sim2real-mp-model-")
    sm.create_model(
        ModelName=model_name,
        PrimaryContainer={"ModelPackageName": mp_arn},
        ExecutionRoleArn=role_arn,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_model(sm, model_name))

    # --- EndpointConfig + Endpoint (serverless: no idle instance cost) ---
    endpoint_config_name = ctx.unique_name("sim2real-mp-epc-")
    sm.create_endpoint_config(
        EndpointConfigName=endpoint_config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "ServerlessConfig": {"MemorySizeInMB": 2048, "MaxConcurrency": 1},
            }
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_endpoint_config(sm, endpoint_config_name))

    endpoint_name = ctx.unique_name("sim2real-mp-ep-")
    sm.create_endpoint(
        EndpointName=endpoint_name,
        EndpointConfigName=endpoint_config_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_endpoint(sm, endpoint_name))

    ep_status = _poll_until(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name)["EndpointStatus"],
        lambda s: s in ("InService", "Failed"),
        timeout_s=900,
        interval_s=15,
    )
    ep_described = sm.describe_endpoint(EndpointName=endpoint_name)
    assert ep_status == "InService", f"endpoint never reached InService: {ep_described.get('FailureReason')}"

    # --- Prove it actually serves inference, not just a green status ---
    runtime = ctx.client("sagemaker-runtime")
    invoke_resp = runtime.invoke_endpoint(
        EndpointName=endpoint_name, ContentType="text/csv", Accept="text/csv", Body=b"3.000,1.500"
    )
    prediction = float(invoke_resp["Body"].read().decode("utf-8").strip())
    assert 0.0 <= prediction <= 1.0, f"expected a binary-logistic probability, got {prediction}"

    # --- Full explicit teardown, verifying nothing is left orphaned ---
    sm.delete_endpoint(EndpointName=endpoint_name)
    _poll_until(
        lambda: _describe_gone(lambda: sm.describe_endpoint(EndpointName=endpoint_name)),
        lambda gone: gone,
        timeout_s=600,
        interval_s=10,
    )
    sm.delete_endpoint_config(EndpointConfigName=endpoint_config_name)
    sm.delete_model(ModelName=model_name)
    sm.delete_model_package(ModelPackageName=model_package_name)

    # SageMaker's Describe* for these four resource types reports a deleted name as
    # ValidationException, not ResourceNotFound.
    ep_gone_code, ep_gone_message = _error(lambda: sm.describe_endpoint(EndpointName=endpoint_name))
    assert ep_gone_code == "ValidationException", (
        f"deleted endpoint {endpoint_name} must read back as ValidationException, got {ep_gone_code!r}"
    )
    expected = f'Could not find endpoint "{endpoint_name}".'
    assert ep_gone_message == expected, f"expected message {expected!r}, got {ep_gone_message!r}"
    epc_gone_code, epc_gone_message = _error(lambda: sm.describe_endpoint_config(EndpointConfigName=endpoint_config_name))
    assert epc_gone_code == "ValidationException", (
        f"deleted endpoint config {endpoint_config_name} must read back as ValidationException, got {epc_gone_code!r}"
    )
    expected = f'Could not find endpoint configuration "{endpoint_config_name}".'
    assert epc_gone_message == expected, f"expected message {expected!r}, got {epc_gone_message!r}"
    model_gone_code, model_gone_message = _error(lambda: sm.describe_model(ModelName=model_name))
    assert model_gone_code == "ValidationException", (
        f"deleted model {model_name} must read back as ValidationException, got {model_gone_code!r}"
    )
    expected = f'Could not find model "{model_name}".'
    assert model_gone_message == expected, f"expected message {expected!r}, got {model_gone_message!r}"
    mp_gone_code, mp_gone_message = _error(lambda: sm.describe_model_package(ModelPackageName=model_package_name))
    assert mp_gone_code == "ValidationException", (
        f"deleted model package {model_package_name} must read back as ValidationException, got {mp_gone_code!r}"
    )
    expected = f"ModelPackage arn:aws:sagemaker:{ctx.region}:{ctx.account}:model-package/{model_package_name} does not exist."
    assert mp_gone_message == expected, f"expected message {expected!r}, got {mp_gone_message!r}"



def _create_bucket(s3, bucket, region):
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region})


def _delete_bucket(s3, bucket):
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_role(iam, role_name):
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _is_gone(exc) -> bool:
    """SageMaker reports a missing endpoint, endpoint config or model as ResourceNotFound or
    ValidationException "Could not find"."""
    error = exc.response["Error"]
    return error["Code"] == "ResourceNotFound" or (
        error["Code"] == "ValidationException" and "Could not find" in error.get("Message", "")
    )


def _delete_endpoint(sm, endpoint_name):
    try:
        sm.delete_endpoint(EndpointName=endpoint_name)
    except ClientError as exc:
        if not _is_gone(exc):
            raise


def _delete_endpoint_config(sm, endpoint_config_name):
    try:
        sm.delete_endpoint_config(EndpointConfigName=endpoint_config_name)
    except ClientError as exc:
        if not _is_gone(exc):
            raise


def _delete_model(sm, model_name):
    try:
        sm.delete_model(ModelName=model_name)
    except ClientError as exc:
        if not _is_gone(exc):
            raise


def _delete_model_package(sm, model_package_arn):
    try:
        sm.delete_model_package(ModelPackageName=model_package_arn)
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] != "ValidationException" or "does not exist" not in error.get("Message", ""):
            raise


def _describe_gone(fn):
    try:
        fn()
        return False
    except ClientError as err:
        code = err.response["Error"]["Code"]
        return code in ("ResourceNotFound", "ValidationException")


def _create_training_job_with_retry(sm, *, retries=10, delay_s=6.0, **kwargs):
    """IAM role trust propagation can lag briefly after create_role/attach_role_policy."""
    last_err = None
    for _ in range(retries):
        try:
            sm.create_training_job(**kwargs)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code in ("ValidationException", "AccessDeniedException") and (
                "assume" in message.lower() or "not authorized" in message.lower()
            ):
                last_err = err
                time.sleep(delay_s)
                continue
            raise
    raise last_err


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as err:
        e = err.response["Error"]
        return e["Code"], e.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
