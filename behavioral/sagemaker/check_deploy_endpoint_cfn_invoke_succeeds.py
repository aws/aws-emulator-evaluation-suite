"""deploy-endpoint-cfn-invoke-succeeds."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-endpoint-cfn-invoke-succeeds"
GROUP = "deploy"
SERVICES = ["sagemaker"]

_SAMPLE_DATA_BUCKET = "sagemaker-sample-files"
_SAMPLE_DATA_KEY = "datasets/tabular/uci_abalone/train_csv/abalone_dataset1_train.csv"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Model+EndpointConfig+Endpoint stack deployed via CloudFormation reaches InService
    and actually accepts a real inference invocation -- not merely CREATE_COMPLETE."""
    # The sagemaker SDK resolves the region's built-in XGBoost image; a missing SDK raises ImportError.
    from sagemaker import image_uris

    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")
    sm_runtime = ctx.client("sagemaker-runtime")

    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_bucket(ctx, s3)

    image_uri = image_uris.retrieve(framework="xgboost", region=ctx.region, version="1.7-1")

    train_data_uri, _label, feature_row = _stage_training_data(s3, bucket)

    training_job_name = ctx.unique_name("sim2real-xgb-train-")
    _create_training_job_with_role_retry(
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
                        "S3Uri": train_data_uri,
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
            }
        ],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        HyperParameters={"objective": "reg:squarederror", "num_round": "5"},
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: _best_effort_delete_training_job(sm, training_job_name))

    job = _poll_until(
        probe=lambda: sm.describe_training_job(TrainingJobName=training_job_name),
        predicate=lambda j: j["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900.0,
        interval_s=15.0,
        description=f"training job {training_job_name} to reach a terminal status",
    )
    assert job["TrainingJobStatus"] == "Completed", (
        f"training job did not complete: {job['TrainingJobStatus']} / {job.get('FailureReason')}"
    )
    model_artifact = job["ModelArtifacts"]["S3ModelArtifacts"]

    model_name = ctx.unique_name("sim2real-model-")
    endpoint_config_name = ctx.unique_name("sim2real-epc-")
    endpoint_name = ctx.unique_name("sim2real-ep-")
    stack_name = ctx.unique_name("sim2real-ep-stack-")

    template = json.dumps(
        {
            "Resources": {
                "Model": {
                    "Type": "AWS::SageMaker::Model",
                    "Properties": {
                        "ModelName": model_name,
                        "ExecutionRoleArn": role_arn,
                        "PrimaryContainer": {"Image": image_uri, "ModelDataUrl": model_artifact},
                    },
                },
                "EndpointConfig": {
                    "Type": "AWS::SageMaker::EndpointConfig",
                    "Properties": {
                        "EndpointConfigName": endpoint_config_name,
                        "ProductionVariants": [
                            {
                                "VariantName": "AllTraffic",
                                "ModelName": model_name,
                                "InitialInstanceCount": 1,
                                "InstanceType": "ml.m5.large",
                            }
                        ],
                    },
                    "DependsOn": "Model",
                },
                "Endpoint": {
                    "Type": "AWS::SageMaker::Endpoint",
                    "Properties": {"EndpointName": endpoint_name, "EndpointConfigName": endpoint_config_name},
                    "DependsOn": "EndpointConfig",
                },
            }
        }
    )

    _deploy_cfn(ctx, cfn, stack_name, template)

    ep = _poll_until(
        probe=lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        predicate=lambda e: e["EndpointStatus"] in ("InService", "Failed"),
        timeout_s=900.0,
        interval_s=15.0,
        description=f"endpoint {endpoint_name} to reach a terminal status",
    )
    assert ep["EndpointStatus"] == "InService", f"endpoint did not reach InService: {ep}"

    response = sm_runtime.invoke_endpoint(
        EndpointName=endpoint_name, ContentType="text/csv", Body=feature_row.encode("utf-8")
    )
    body = response["Body"].read().decode("utf-8").strip()
    assert body, "expected a non-empty prediction body from the deployed endpoint"
    float(body.split(",")[0])  # raises if the endpoint didn't return a real numeric prediction


# ===== helpers =====
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
        from botocore.exceptions import ClientError

        for delete in (
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                delete()
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_training_job_with_role_retry(sm, **kwargs):
    """SageMaker validates RoleArn assumability synchronously; a role created moments ago
    may not have propagated through IAM yet. Retry only that specific, transient error."""
    from botocore.exceptions import ClientError

    last_err: Exception | None = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        try:
            sm.create_training_job(**kwargs)
            return
        except ClientError as e:
            last_err = e
            message = e.response.get("Error", {}).get("Message", "")
            if e.response.get("Error", {}).get("Code") == "ValidationException" and "role" in message.lower():
                time.sleep(3)
                continue
            raise
    raise AssertionError(f"could not create training job after IAM role propagation retries: {last_err}")


def _create_bucket(ctx, s3):
    # AmazonSageMakerFullAccess scopes its S3 permissions to bucket names containing
    # "sagemaker" (other bucket names get AccessDenied on GetObject/PutObject), so the name
    # must carry that substring.
    bucket = ctx.unique_name("sagemaker-sim2real-out-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-owner", "Value": "behavioral-suite"}]}
    )

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _stage_training_data(s3, bucket: str) -> tuple[str, str, str]:
    """SageMaker's training-job S3 data channel requires the input bucket to be in the SAME
    region as the training job; ``sagemaker-sample-files`` lives in a single region and real AWS
    rejects it as an out-of-region source (ValidationException: 'must be addressed using the
    specified endpoint'), even though a plain S3 GetObject against it succeeds cross-region. So
    the sample CSV is re-staged into our own region-local bucket before training reads it."""
    body = s3.get_object(Bucket=_SAMPLE_DATA_BUCKET, Key=_SAMPLE_DATA_KEY)["Body"].read()
    first_line = body.decode("utf-8").splitlines()[0]
    fields = first_line.split(",")
    label, feature_row = fields[0], ",".join(fields[1:])
    key = "train/abalone_dataset1_train.csv"
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    return f"s3://{bucket}/{key}", label, feature_row


def _best_effort_delete_training_job(sm, name):
    from botocore.exceptions import ClientError

    try:
        sm.stop_training_job(TrainingJobName=name)
    except ClientError as e:
        # A job that has left InProgress refuses the stop with ValidationException; anything else fails.
        if e.response["Error"]["Code"] == "ResourceNotFound":
            return
        if e.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=name)["TrainingJobStatus"] == "InProgress":
            raise
    # DeleteTrainingJob needs a terminal job, so wait out InProgress/Stopping first.
    deadline = time.monotonic() + 180.0
    while (status := sm.describe_training_job(TrainingJobName=name)["TrainingJobStatus"]) in ("InProgress", "Stopping"):
        if time.monotonic() >= deadline:
            raise TimeoutError(f"training job {name} still {status} 180s after StopTrainingJob")
        time.sleep(2)
    try:
        sm.delete_training_job(TrainingJobName=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _deploy_cfn(ctx, cfn, stack_name: str, template: str) -> None:
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real-owner", "Value": "behavioral-suite"}],
    )

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 500})

    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600})


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    raise AssertionError(f"timed out after {timeout_s}s waiting for {description}; last observed: {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
