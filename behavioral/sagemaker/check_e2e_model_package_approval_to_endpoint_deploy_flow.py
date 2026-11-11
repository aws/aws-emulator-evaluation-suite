"""e2e-model-package-approval-to-endpoint-deploy-flow."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-model-package-approval-to-endpoint-deploy-flow"
GROUP = "e2e"
SERVICES = ["sagemaker"]

_SAMPLE_DATA_BUCKET = "sagemaker-sample-files"
_SAMPLE_DATA_KEY = "datasets/tabular/uci_abalone/train_csv/abalone_dataset1_train.csv"

# Account IDs that own the legacy built-in "xgboost" algorithm container image, by
# region (the AWS docs page enumerating these per-region registry paths was retired --
# see
# https://docs.aws.amazon.com/sagemaker/latest/dg-ecr-paths/sagemaker-algo-docker-registry-paths.html
# -- these are the well-known SageMaker built-in-algorithm ECR account IDs). Resolved this way, not
# via the `sagemaker` SDK's `image_uris.retrieve`, because that helper lives only in the classic v2
# SDK API surface and is absent from v3. Deliberately the legacy "xgboost" repository, not the newer
# "sagemaker-xgboost" framework-container repository: SageMaker training compute gets ECR
# "pull access denied" (no cross-account resource policy) for "sagemaker-xgboost" from these
# registry accounts.
_XGBOOST_REGISTRY_ACCOUNT = {
    "us-east-1": "811284229777",
    "us-east-2": "825641698319",
    "us-west-1": "632365934929",
    "us-west-2": "433757028032",
    "eu-west-1": "685385470294",
    "eu-central-1": "813361260812",
    "ap-northeast-1": "501404015308",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "544295431143",
    "ca-central-1": "469771592824",
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A model package created in a group, deployed behind an endpoint, results in a
    running endpoint traceable to the exact package version; deleting the endpoint and
    group cleans up without orphaning state."""
    registry_account = _XGBOOST_REGISTRY_ACCOUNT.get(ctx.region)
    if registry_account is None:
        raise AssertionError(f"no known built-in XGBoost algorithm image account for region {ctx.region}")
    image_uri = f"{registry_account}.dkr.ecr.{ctx.region}.amazonaws.com/xgboost:1"

    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    sm_runtime = ctx.client("sagemaker-runtime")

    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_bucket(ctx, s3)
    # SageMaker's own backend read for training input needs the source in-region: the
    # public sample bucket isn't universally reachable that way (cross-region it fails with
    # "must be addressed using the specified endpoint"), so stage a copy into the
    # bucket this check already owns, which is created in ctx.region.
    train_key = "train/train.csv"
    label, feature_row = _stage_sample_data(s3, bucket, train_key)

    training_job_name = ctx.unique_name("sim2real-xgb-train-")
    _create_training_job_with_retry(
        sm,
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
                        "S3Uri": f"s3://{bucket}/{train_key}",
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
            }
        ],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        # The legacy built-in "xgboost:1" algorithm container (see the image-selection
        # comment above) only accepts its older objective vocabulary; it rejects
        # "reg:squarederror" with the accepted-enum error naming "reg:linear"
        # as its squared-error-regression equivalent.
        HyperParameters={"objective": "reg:linear", "num_round": "5"},
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: _best_effort_delete_training_job(sm, training_job_name))

    job = _poll_until(
        probe=lambda: sm.describe_training_job(TrainingJobName=training_job_name),
        predicate=lambda j: j["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900.0,
        interval_s=15.0,
        description=f"training job {training_job_name} to leave InProgress",
    )
    assert job["TrainingJobStatus"] == "Completed", (
        f"training job did not complete: {job['TrainingJobStatus']} ({job.get('FailureReason')})"
    )
    model_artifact = job["ModelArtifacts"]["S3ModelArtifacts"]

    group_name = ctx.unique_name("sim2real-mpg-")
    sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name)))

    # A versioned model package (ModelPackageGroupName set) rejects its own Tags param --
    # real AWS: "Tags are not supported in Model Package versions. Please add them to
    # the Model Package Group." The group above already carries the tag.
    pkg_arn = sm.create_model_package(
        ModelPackageGroupName=group_name,
        InferenceSpecification={
            "Containers": [{"Image": image_uri, "ModelDataUrl": model_artifact}],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
        },
        ModelApprovalStatus="Approved",
    )["ModelPackageArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: sm.delete_model_package(ModelPackageName=pkg_arn)))

    model_name = ctx.unique_name("sim2real-model-")
    sm.create_model(
        ModelName=model_name,
        ExecutionRoleArn=role_arn,
        PrimaryContainer={"ModelPackageName": pkg_arn},
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: sm.delete_model(ModelName=model_name)))

    endpoint_config_name = ctx.unique_name("sim2real-epc-")
    sm.create_endpoint_config(
        EndpointConfigName=endpoint_config_name,
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
    ctx.on_cleanup(
        lambda: _best_effort(lambda: sm.delete_endpoint_config(EndpointConfigName=endpoint_config_name))
    )

    endpoint_name = ctx.unique_name("sim2real-ep-")
    sm.create_endpoint(
        EndpointName=endpoint_name,
        EndpointConfigName=endpoint_config_name,
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: sm.delete_endpoint(EndpointName=endpoint_name)))

    ep = _poll_until(
        probe=lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        predicate=lambda e: e["EndpointStatus"] in ("InService", "Failed"),
        timeout_s=900.0,
        interval_s=15.0,
        description=f"endpoint {endpoint_name} to leave Creating",
    )
    assert ep["EndpointStatus"] == "InService", f"endpoint did not reach InService: {ep}"

    # Traceable to the exact package version: the model backing the live endpoint's
    # single production variant was created directly from this model package ARN.
    described_model = sm.describe_model(ModelName=model_name)
    assert described_model["PrimaryContainer"]["ModelPackageName"] == pkg_arn, (
        f"expected model {model_name} to trace to package {pkg_arn}, "
        f"got {described_model['PrimaryContainer'].get('ModelPackageName')!r}"
    )

    response = sm_runtime.invoke_endpoint(
        EndpointName=endpoint_name, ContentType="text/csv", Body=feature_row.encode("utf-8")
    )
    body = response["Body"].read().decode("utf-8").strip()
    assert body, "expected a non-empty prediction body from the deployed endpoint"
    prediction = float(body.split(",")[0])
    # The row is the first training row, so the trained regressor's prediction lies near its
    # label (5 boosting rounds shrink it toward the 0.5 base score by under a fifth).
    expected = float(label)
    tolerance = max(5.0, 0.5 * abs(expected))
    assert abs(prediction - expected) < tolerance, (
        f"endpoint predicted {prediction!r} for the first training row, whose label is {expected}; "
        f"expected within {tolerance} of it (body {body[:200]!r})"
    )

    # Tear down through the front door (not just via cleanup callbacks) and verify no
    # orphaned state is left behind.
    sm.delete_endpoint(EndpointName=endpoint_name)
    deleted_code, deleted_message = _refusal_eventually(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name), timeout_s=120.0, interval_s=5.0
    )
    assert deleted_code == "ValidationException", (
        f"expected endpoint {endpoint_name} to be gone after delete, describe returned {deleted_code!r}"
    )
    expected = f'Could not find endpoint "{endpoint_name}".'
    assert deleted_message == expected, f"expected message {expected!r}, got {deleted_message!r}"
    sm.delete_endpoint_config(EndpointConfigName=endpoint_config_name)
    sm.delete_model(ModelName=model_name)
    sm.delete_model_package(ModelPackageName=pkg_arn)
    sm.delete_model_package_group(ModelPackageGroupName=group_name)

    final_code, final_message = _error(lambda: sm.describe_model_package_group(ModelPackageGroupName=group_name))
    # DescribeModelPackageGroup answers a deleted group with ValidationException, not
    # ResourceNotFound (unlike DescribeEndpoint, which can answer either).
    assert final_code == "ValidationException", (
        f"model package group was not fully cleaned up: {final_code!r}"
    )
    expected = f"ModelPackageGroup arn:aws:sagemaker:{ctx.region}:{ctx.account}:model-package-group/{group_name} does not exist."
    assert final_message == expected, f"expected message {expected!r}, got {final_message!r}"


# ===== helpers =====
def _create_training_job_with_retry(sm, *, retries=10, delay_s=6.0, **kwargs):
    """IAM role trust propagation can lag briefly after create_role/attach_role_policy,
    even after the role is readable back via get_role: SageMaker's synchronous
    CreateTrainingJob validation both assume-role's the role AND separately lists the
    input S3 prefix using freshly-assumed credentials from that same role, and either
    probe can transiently see a not-yet-propagated/not-yet-recognized credential."""
    from botocore.exceptions import ClientError

    last_err = None
    for _ in range(retries):
        try:
            sm.create_training_job(**kwargs)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "").lower()
            if code in ("ValidationException", "AccessDeniedException") and (
                "assume" in message
                or "not authorized" in message
                or "access key id" in message
                or "no s3 objects found" in message
            ):
                last_err = err
                time.sleep(delay_s)
                continue
            raise
    raise last_err


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


def _best_effort(fn):
    """Run a teardown call; return only when the resource is already gone, raise the rest."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        error = exc.response["Error"]
        message = error.get("Message", "").lower()
        if error["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket"):
            return
        if error["Code"] != "ValidationException" or not (
            "could not find" in message or "does not exist" in message
        ):
            raise


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        _best_effort(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
        _best_effort(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    # IAM is eventually consistent: wait for the role to be readable back before handing
    # it to SageMaker, which will otherwise reject the assume-role trust as not-yet-visible.
    _poll_until(
        probe=lambda: iam.get_role(RoleName=role_name)["Role"]["Arn"],
        predicate=lambda arn: arn == role_arn,
        timeout_s=30.0,
        interval_s=2.0,
        description=f"role {role_name} to become visible to IAM reads",
    )
    return role_arn


def _create_bucket(ctx, s3):
    # AmazonSageMakerFullAccess (attached to the training/hosting role below) scopes its S3
    # grant to bucket names containing "sagemaker"; s3:GetObject against a bucket whose
    # name lacks it is denied with AccessDenied.
    bucket = ctx.unique_name("sagemaker-sim2real-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                _best_effort(lambda k=obj["Key"]: s3.delete_object(Bucket=bucket, Key=k))
        _best_effort(lambda: s3.delete_bucket(Bucket=bucket))

    ctx.on_cleanup(_cleanup)
    return bucket


def _stage_sample_data(s3, bucket, key):
    body = s3.get_object(Bucket=_SAMPLE_DATA_BUCKET, Key=_SAMPLE_DATA_KEY)["Body"].read()
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    first_line = body.decode("utf-8").splitlines()[0]
    fields = first_line.split(",")
    return fields[0], ",".join(fields[1:])


def _best_effort_delete_training_job(sm, name):
    from botocore.exceptions import ClientError

    try:
        sm.stop_training_job(TrainingJobName=name)
    except ClientError as err:
        # A job that is not InProgress refuses the stop with ValidationException; anything else fails.
        if err.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=name)["TrainingJobStatus"] == "InProgress":
            raise
    # DeleteTrainingJob is refused with ResourceInUse while the job is still stopping.
    deadline = time.monotonic() + 180.0
    while True:
        try:
            _best_effort(lambda: sm.delete_training_job(TrainingJobName=name))
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    if predicate(last):
        return last
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description} (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
