"""deploy-endpoint-stack-reaches-inservice-and-serves."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-endpoint-stack-reaches-inservice-and-serves"
GROUP = "deploy"
SERVICES = ["sagemaker"]

# AWS's own per-region ECR account that hosts the linear-learner built-in algorithm
# image; these accounts are fixed by AWS and differ per region, so the region
# literals below are the resource identity, not a shortcut.
_LINEAR_LEARNER_REGISTRY = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "eu-west-1": "438346466558",
    "eu-central-1": "664544806723",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-south-1": "991648021394",
    "ca-central-1": "469771592824",
}

_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ModelImage": {"Type": "String"},
            "ModelDataUrl": {"Type": "String"},
            "ExecutionRoleArn": {"Type": "String"},
            "ModelNameParam": {"Type": "String"},
            "EndpointConfigNameParam": {"Type": "String"},
            "EndpointNameParam": {"Type": "String"},
        },
        "Resources": {
            "SmModel": {
                "Type": "AWS::SageMaker::Model",
                "Properties": {
                    "ModelName": {"Ref": "ModelNameParam"},
                    "ExecutionRoleArn": {"Ref": "ExecutionRoleArn"},
                    "PrimaryContainer": {
                        "Image": {"Ref": "ModelImage"},
                        "ModelDataUrl": {"Ref": "ModelDataUrl"},
                    },
                },
            },
            "SmEndpointConfig": {
                "Type": "AWS::SageMaker::EndpointConfig",
                "Properties": {
                    "EndpointConfigName": {"Ref": "EndpointConfigNameParam"},
                    "ProductionVariants": [
                        {
                            "VariantName": "AllTraffic",
                            "ModelName": {"Ref": "ModelNameParam"},
                            "InitialInstanceCount": 1,
                            "InstanceType": "ml.m5.large",
                        }
                    ],
                },
                "DependsOn": "SmModel",
            },
            "SmEndpoint": {
                "Type": "AWS::SageMaker::Endpoint",
                "Properties": {
                    "EndpointName": {"Ref": "EndpointNameParam"},
                    "EndpointConfigName": {"Ref": "EndpointConfigNameParam"},
                },
                "DependsOn": "SmEndpointConfig",
            },
        },
    }
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation stack of AWS::SageMaker::Model, EndpointConfig and Endpoint produces an
    endpoint that DescribeEndpoint reports InService with the template's config/model linkage,
    not merely a CREATE_COMPLETE stack."""
    sm = ctx.client("sagemaker")
    cfn = ctx.client("cloudformation")
    role_arn = _create_sagemaker_role(ctx)
    _job_name, model_artifacts, image = _run_linear_learner_training_job(ctx, role_arn)

    model_name = ctx.unique_name("sim2real-sm-cfn-model-")
    config_name = ctx.unique_name("sim2real-sm-cfn-epc-")
    endpoint_name = ctx.unique_name("sim2real-sm-cfn-ep-")
    stack_name = ctx.unique_name("sim2real-sm-cfn-stack-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "ModelImage", "ParameterValue": image},
            {"ParameterKey": "ModelDataUrl", "ParameterValue": model_artifacts},
            {"ParameterKey": "ExecutionRoleArn", "ParameterValue": role_arn},
            {"ParameterKey": "ModelNameParam", "ParameterValue": model_name},
            {"ParameterKey": "EndpointConfigNameParam", "ParameterValue": config_name},
            {"ParameterKey": "EndpointNameParam", "ParameterValue": endpoint_name},
        ],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    _, stack_desc = _poll_until(
        probe=lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0],
        predicate=lambda s: s["StackStatus"]
        in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED", "ROLLBACK_FAILED"),
        timeout_s=900,
        interval_s=20,
    )
    assert stack_desc["StackStatus"] == "CREATE_COMPLETE", (
        f"stack did not reach CREATE_COMPLETE: {stack_desc['StackStatus']}"
    )

    # A completed stack is not the finish line: the endpoint it created must actually
    # be serving.
    _, ep_desc = _poll_until(
        probe=lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        predicate=lambda d: d["EndpointStatus"] in ("InService", "Failed"),
        timeout_s=900,
        interval_s=20,
    )
    assert ep_desc["EndpointStatus"] == "InService", (
        f"endpoint did not reach InService: {ep_desc.get('FailureReason')}"
    )
    assert ep_desc["EndpointConfigName"] == config_name, (
        f"endpoint should be linked to {config_name!r}, got {ep_desc['EndpointConfigName']!r}"
    )

    desc_cfg = sm.describe_endpoint_config(EndpointConfigName=config_name)
    assert desc_cfg["ProductionVariants"][0]["ModelName"] == model_name, (
        f"endpoint config should reference model {model_name!r}, got "
        f"{desc_cfg['ProductionVariants'][0]['ModelName']!r}"
    )

    desc_model = sm.describe_model(ModelName=model_name)
    assert desc_model["PrimaryContainer"]["ModelDataUrl"] == model_artifacts, (
        f"model should reference training artifacts {model_artifacts!r}, got "
        f"{desc_model['PrimaryContainer']['ModelDataUrl']!r}"
    )
    assert desc_model["ExecutionRoleArn"] == role_arn, (
        f"model should carry execution role {role_arn!r}, got {desc_model['ExecutionRoleArn']!r}"
    )


# ===== helpers =====
def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value, value
        time.sleep(interval_s)
        value = probe()
    return value, value


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-cfn-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    # AmazonSageMakerFullAccess alone grants S3 access only to buckets/objects whose
    # name contains "sagemaker" -- this check's bucket does not, so the training job's
    # GetObject on the training CSV was denied on real AWS without this second policy.
    policy_arns = (
        "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    )
    for policy_arn in policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        deletes = [lambda arn=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=arn) for arn in policy_arns]
        for delete in [*deletes, lambda: iam.delete_role(RoleName=role_name)]:
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
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    # A freshly-created IAM role can exist (get_role succeeds) before its trust policy
    # has propagated far enough for the sagemaker.amazonaws.com principal to assume it.
    # Poll the actual call that needs the role instead of guessing a fixed sleep.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "").lower()
            if code == "ValidationException" and "role" in message and "assum" in message:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"role never became assumable within {timeout_s}s: {last_exc}")


def _linear_learner_image(region):
    account = _LINEAR_LEARNER_REGISTRY.get(region)
    if not account:
        raise AssertionError(
            f"no known linear-learner built-in algorithm registry account for "
            f"region {region!r}; extend _LINEAR_LEARNER_REGISTRY to close this gap"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:1"


def _upload_training_data(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-sm-cfn-data-").lower()
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )

    def _cleanup():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)

    rng = random.Random(7)
    rows = []
    for _ in range(200):
        f1, f2, f3 = rng.random(), rng.random(), rng.random()
        label = f1 * 2.0 + f2 - f3 + rng.random() * 0.01
        rows.append(f"{label},{f1},{f2},{f3}")
    key = "train/data.csv"
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(rows).encode("utf-8"))
    return bucket, key


def _run_linear_learner_training_job(ctx, role_arn):
    sm = ctx.client("sagemaker")
    bucket, key = _upload_training_data(ctx)
    image = _linear_learner_image(ctx.region)
    job_name = ctx.unique_name("sim2real-sm-cfn-train-")

    _retry_role_propagation(
        lambda: sm.create_training_job(
            TrainingJobName=job_name,
            AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "File"},
            RoleArn=role_arn,
            InputDataConfig=[
                {
                    "ChannelName": "train",
                    "DataSource": {
                        "S3DataSource": {
                            "S3DataType": "S3Prefix",
                            "S3Uri": f"s3://{bucket}/{key}",
                            "S3DataDistributionType": "FullyReplicated",
                        }
                    },
                    "ContentType": "text/csv",
                    "CompressionType": "None",
                }
            ],
            OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
            StoppingCondition={"MaxRuntimeInSeconds": 900},
            HyperParameters={
                "feature_dim": "3",
                "predictor_type": "regressor",
                "mini_batch_size": "20",
                "epochs": "3",
            },
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
    )

    def _cleanup():
        try:
            sm.stop_training_job(TrainingJobName=job_name)
        except ClientError as exc:
            # A job that is not InProgress refuses the stop with ValidationException; anything else fails.
            if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
                raise

    ctx.on_cleanup(_cleanup)

    _, desc = _poll_until(
        probe=lambda: sm.describe_training_job(TrainingJobName=job_name),
        predicate=lambda d: d["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900,
        interval_s=15,
    )
    if desc["TrainingJobStatus"] != "Completed":
        raise AssertionError(
            f"training job did not complete: status={desc['TrainingJobStatus']} "
            f"reason={desc.get('FailureReason')}"
        )
    return job_name, desc["ModelArtifacts"]["S3ModelArtifacts"], image


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
