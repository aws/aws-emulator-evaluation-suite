"""deploy-model-endpoint-cfn-serves-inference."""
from __future__ import annotations

import json
import math
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-model-endpoint-cfn-serves-inference"
GROUP = "deploy"
SERVICES = ["sagemaker"]

_SAGEMAKER_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}
_SAGEMAKER_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"

# Fallback SageMaker built-in-algorithm XGBoost image URIs, used only if the `sagemaker`
# Python SDK (which carries the authoritative per-region account-id table) is unavailable.
_XGBOOST_IMAGE_FALLBACK = {
    "us-east-1": "683313688378.dkr.ecr.us-east-1.amazonaws.com/sagemaker-xgboost:1.5-1",
    "us-west-2": "246618743249.dkr.ecr.us-west-2.amazonaws.com/sagemaker-xgboost:1.5-1",
}

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

# The check trains its own tiny booster on synthetic data: public sample artifacts can
# disappear (NoSuchKey), and the feature width is then known rather than guessed.
_FEATURE_COUNT = 2


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A CloudFormation Model+EndpointConfig+Endpoint stack reaches InService wired to the
    template's config and model names, InvokeEndpoint returns a finite prediction near the
    trained label, and after stack deletion DescribeEndpoint reports the endpoint gone."""
    # The endpoint bills while up (~10-15 min to InService): one ml.m5.large variant,
    # torn down with the stack.
    image_uri = _resolve_xgboost_image_uri(ctx)

    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")
    # One teardown deadline for this run, started by the first teardown.
    teardown: dict[str, float] = {}
    smr = ctx.client("sagemaker-runtime")

    role_name = ctx.unique_name("sim2real-sagemaker-ep-role-")
    role_arn = _create_role(ctx, iam, role_name)

    bucket = _create_bucket(ctx, s3)
    _upload_training_csv(s3, bucket)
    model_data_url = _train_xgboost_model(ctx, sm, role_arn, image_uri, bucket, teardown)

    model_name = ctx.unique_name("sim2real-sagemaker-model-")
    config_name = ctx.unique_name("sim2real-sagemaker-epcfg-")
    endpoint_name = ctx.unique_name("sim2real-sagemaker-ep-")
    stack_name = ctx.unique_name("sim2real-sagemaker-ep-stack-")

    template_body = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "RoleArn": {"Type": "String"},
                "ImageUri": {"Type": "String"},
                "ModelDataUrl": {"Type": "String"},
                "ModelName": {"Type": "String"},
                "EndpointConfigName": {"Type": "String"},
                "EndpointName": {"Type": "String"},
            },
            "Resources": {
                "Model": {
                    "Type": "AWS::SageMaker::Model",
                    "Properties": {
                        "ModelName": {"Ref": "ModelName"},
                        "ExecutionRoleArn": {"Ref": "RoleArn"},
                        "PrimaryContainer": {
                            "Image": {"Ref": "ImageUri"},
                            "ModelDataUrl": {"Ref": "ModelDataUrl"},
                        },
                    },
                },
                "EndpointConfig": {
                    "Type": "AWS::SageMaker::EndpointConfig",
                    "DependsOn": "Model",
                    "Properties": {
                        "EndpointConfigName": {"Ref": "EndpointConfigName"},
                        "ProductionVariants": [
                            {
                                "VariantName": "AllTraffic",
                                "ModelName": {"Ref": "ModelName"},
                                "InitialInstanceCount": 1,
                                "InstanceType": "ml.m5.large",
                            }
                        ],
                    },
                },
                "Endpoint": {
                    "Type": "AWS::SageMaker::Endpoint",
                    "DependsOn": "EndpointConfig",
                    "Properties": {
                        "EndpointName": {"Ref": "EndpointName"},
                        "EndpointConfigName": {"Ref": "EndpointConfigName"},
                    },
                },
            },
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=[
            {"ParameterKey": "RoleArn", "ParameterValue": role_arn},
            {"ParameterKey": "ImageUri", "ParameterValue": image_uri},
            {"ParameterKey": "ModelDataUrl", "ParameterValue": model_data_url},
            {"ParameterKey": "ModelName", "ParameterValue": model_name},
            {"ParameterKey": "EndpointConfigName", "ParameterValue": config_name},
            {"ParameterKey": "EndpointName", "ParameterValue": endpoint_name},
        ],
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name, _teardown_left(teardown)))

    status = _wait_for_stack_terminal(cfn, stack_name, timeout_s=1800.0, interval_s=20.0)
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE, got {status}"

    endpoint = sm.describe_endpoint(EndpointName=endpoint_name)
    assert endpoint["EndpointStatus"] == "InService", (
        f"expected EndpointStatus InService, got {endpoint['EndpointStatus']}"
    )
    assert endpoint["EndpointConfigName"] == config_name, (
        f"endpoint wired to EndpointConfigName {endpoint['EndpointConfigName']!r}, "
        f"expected the stack's {config_name!r}"
    )

    config = sm.describe_endpoint_config(EndpointConfigName=config_name)
    variants = config["ProductionVariants"]
    assert len(variants) == 1, f"expected exactly 1 production variant, got {len(variants)}"
    assert variants[0]["ModelName"] == model_name, (
        f"variant wired to ModelName {variants[0]['ModelName']!r}, expected {model_name!r}"
    )
    assert variants[0]["InstanceType"] == "ml.m5.large", (
        f"expected InstanceType ml.m5.large, got {variants[0]['InstanceType']!r}"
    )

    # (x1=5, x2=3) is a training row (i=15), so the expected label is known.
    query_x1, query_x2 = 5.0, 3.0
    row = f"{query_x1},{query_x2}".encode("ascii")
    resp = smr.invoke_endpoint(
        EndpointName=endpoint_name, ContentType="text/csv", Accept="text/csv", Body=row
    )
    payload = resp["Body"].read().decode("utf-8").strip()
    prediction = float(payload.split(",")[0])
    assert math.isfinite(prediction), (
        f"endpoint returned a non-finite prediction {prediction!r} for a real "
        f"{_FEATURE_COUNT}-feature InvokeEndpoint call -- not real inference"
    )
    expected = 3.0 * query_x1 + 2.0 * query_x2 + 1.0
    assert abs(prediction - expected) < 10.0, (
        f"endpoint trained on a noise-free label = 3*x1 + 2*x2 + 1 predicted {prediction!r} "
        f"for (x1={query_x1}, x2={query_x2}); expected something near {expected}"
    )

    _delete_stack(cfn, stack_name, timeout_s=1800.0)
    try:
        sm.describe_endpoint(EndpointName=endpoint_name)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "ValidationException", (
            f"expected ValidationException for a deleted endpoint, got {code}: {message}"
        )
        expected = f'Could not find endpoint "{endpoint_name}".'
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError(
            f"endpoint {endpoint_name} is still describable after the stack that "
            "created it was deleted"
        )


def _resolve_xgboost_image_uri(ctx: Any) -> str:
    try:
        from sagemaker import image_uris  # type: ignore
    except ImportError:
        return _XGBOOST_IMAGE_FALLBACK[ctx.region]
    return image_uris.retrieve(framework="xgboost", region=ctx.region, version="1.5-1")


def _create_role(ctx: Any, iam, role_name: str) -> str:
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_SAGEMAKER_TRUST_POLICY),
        Tags=_TAGS,
    )
    role_arn = resp["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_SAGEMAKER_MANAGED_POLICY_ARN)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=_SAGEMAKER_MANAGED_POLICY_ARN)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    _wait_for_role_usable(iam, role_name, _SAGEMAKER_MANAGED_POLICY_ARN)
    return role_arn


def _wait_for_role_usable(
    iam, role_name: str, policy_arn: str, *, timeout_s: float = 60.0, settle_s: float = 10.0
) -> None:
    """Wait out IAM propagation: require IAM's view of the role and attached policy to stay
    stable for `settle_s`, because SageMaker's own view of the role cannot be read."""
    deadline = time.monotonic() + timeout_s
    settled_since: float | None = None
    while time.monotonic() < deadline:
        try:
            attached = {
                p["PolicyArn"]
                for p in iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"]
            }
        except Exception:
            attached = set()
        if policy_arn in attached:
            now = time.monotonic()
            if settled_since is None:
                settled_since = now
            elif now - settled_since >= settle_s:
                return
        else:
            settled_since = None
        time.sleep(2.0)
    raise AssertionError(
        f"role {role_name} never showed {policy_arn} attached (stably, for {settle_s}s) "
        f"within {timeout_s}s"
    )


def _create_bucket(ctx: Any, s3) -> str:
    bucket = ctx.unique_name("sim2real-sagemaker-model-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})

    def _cleanup() -> None:
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        finally:
            s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _upload_training_csv(s3, bucket: str) -> None:
    """Upload synthetic training data with label = 3*x1 + 2*x2 + 1."""
    lines = []
    for i in range(50):
        x1 = float(i % 10)
        x2 = float((i * 3) % 7)
        label = 3.0 * x1 + 2.0 * x2 + 1.0
        lines.append(f"{label},{x1},{x2}")
    body = ("\n".join(lines) + "\n").encode("utf-8")
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=body)


def _train_xgboost_model(ctx: Any, sm, role_arn: str, image_uri: str, bucket: str, teardown: dict) -> str:
    job_name = ctx.unique_name("sim2real-sagemaker-ep-train-")
    sm.create_training_job(
        TrainingJobName=job_name,
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
        HyperParameters={"objective": "reg:squarederror", "num_round": "10"},
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _best_effort_delete_training_job(sm, job_name, teardown))

    job = _wait_for_training_job_terminal(sm, job_name, timeout_s=900.0, interval_s=15.0)
    assert job["TrainingJobStatus"] == "Completed", (
        f"training job {job_name} did not complete: {job['TrainingJobStatus']} / "
        f"{job.get('FailureReason')}"
    )
    return job["ModelArtifacts"]["S3ModelArtifacts"]


def _wait_for_training_job_terminal(sm, job_name: str, timeout_s: float, interval_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    desc: dict[str, Any] = {}
    while time.monotonic() < deadline:
        desc = sm.describe_training_job(TrainingJobName=job_name)
        if desc["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"):
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"training job {job_name} did not finish within {timeout_s}s: {desc}")


def _teardown_left(teardown: dict) -> float:
    """Seconds left on the run's one teardown deadline: 1140 s from the first teardown, inside the
    suite's 1200 s cleanup budget."""
    if "deadline" not in teardown:
        teardown["deadline"] = time.monotonic() + 1140.0
    return max(0.0, teardown["deadline"] - time.monotonic())


def _best_effort_delete_training_job(sm, job_name: str, teardown: dict) -> None:
    """Stop the job only while it is InProgress, wait until it leaves InProgress/Stopping, then
    delete it, retrying ResourceInUse every 2 s; ResourceNotFound is gone. Failures raise."""
    deadline = time.monotonic() + _teardown_left(teardown)
    try:
        status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFound":
            return
        raise
    if status == "InProgress":
        sm.stop_training_job(TrainingJobName=job_name)
    while status in ("InProgress", "Stopping"):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"training job {job_name} still {status} at the teardown deadline")
        time.sleep(2)
        status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
    while True:
        try:
            sm.delete_training_job(TrainingJobName=job_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFound":
                return
            if code != "ResourceInUse" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_for_stack_terminal(cfn, stack_name: str, timeout_s: float, interval_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    status = "UNKNOWN"
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        status = resp["Stacks"][0]["StackStatus"]
        if status.endswith("_COMPLETE") or status.endswith("_FAILED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached a terminal status (last={status})")


def _delete_stack(cfn, stack_name: str, timeout_s: float) -> None:
    """Delete the stack and wait, polling every 2 s, until it is gone or DELETE_COMPLETE."""
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except ClientError as exc:
            # CloudFormation answers ValidationError "Stack with id ... does not exist" once the
            # stack is gone.
            if exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in str(exc):
                return
            raise
        status = resp["Stacks"][0]["StackStatus"]
        if status == "DELETE_COMPLETE":
            return
        if status.endswith("_FAILED"):
            raise AssertionError(f"stack {stack_name} delete failed with status {status}")
        time.sleep(2.0)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s:.0f}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
