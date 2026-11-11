"""deploy-endpoint-cfn-serves-config."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-endpoint-cfn-serves-config"
GROUP = "deploy"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Model/EndpointConfig/Endpoint stack reaches InService with the exact
    deployed linkage (config, model, image, artifact, instance counts) in the Describe reads,
    and UpdateEndpoint to a nonexistent config fails ValidationException "Could not find"."""
    image_uri = _linear_learner_image_uri(ctx.region)

    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    sm = ctx.client("sagemaker")
    cfn = ctx.client("cloudformation")

    bucket = ctx.unique_name("sim2real-sagemaker-").lower()
    _create_bucket(ctx, s3, bucket)

    train_csv = _tiny_binary_classification_csv()
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=train_csv.encode("utf-8"))
    train_uri = f"s3://{bucket}/train/train.csv"
    output_uri = f"s3://{bucket}/output/"

    role_name = ctx.unique_name("sim2real-sm-ep-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
        "arn:aws:iam::aws:policy/AmazonS3FullAccess",
    ):
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        ctx.on_cleanup(
            lambda p=policy_arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=p)
        )

    training_job_name = ctx.unique_name("sim2real-sm-ll-train-")
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
                        "S3Uri": train_uri,
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
            }
        ],
        OutputDataConfig={"S3OutputPath": output_uri},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        HyperParameters={
            "feature_dim": "2",
            "predictor_type": "binary_classifier",
            "epochs": "3",
            "mini_batch_size": "10",
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    described_job = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=training_job_name),
        lambda d: d["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900,
        interval_s=15,
    )
    assert described_job["TrainingJobStatus"] == "Completed", (
        f"training job ended in {described_job['TrainingJobStatus']}: "
        f"{described_job.get('FailureReason')}"
    )
    model_data_url = described_job["ModelArtifacts"]["S3ModelArtifacts"]

    model_name = ctx.unique_name("sim2real-sm-ep-model-")
    config_name = ctx.unique_name("sim2real-sm-ep-config-")
    endpoint_name = ctx.unique_name("sim2real-sm-ep-")
    variant_name = "AllTraffic"
    stack_name = ctx.unique_name("sim2real-sm-ep-stack-")

    template = json.dumps(
        {
            "Parameters": {
                "ModelName": {"Type": "String"},
                "ConfigName": {"Type": "String"},
                "EndpointName": {"Type": "String"},
                "RoleArn": {"Type": "String"},
                "Image": {"Type": "String"},
                "ModelDataUrl": {"Type": "String"},
            },
            "Resources": {
                "Model": {
                    "Type": "AWS::SageMaker::Model",
                    "Properties": {
                        "ModelName": {"Ref": "ModelName"},
                        "ExecutionRoleArn": {"Ref": "RoleArn"},
                        "PrimaryContainer": {
                            "Image": {"Ref": "Image"},
                            "ModelDataUrl": {"Ref": "ModelDataUrl"},
                        },
                        "Tags": [{"Key": "sim2real", "Value": CHECK}],
                    },
                },
                "EndpointConfig": {
                    "Type": "AWS::SageMaker::EndpointConfig",
                    "Properties": {
                        "EndpointConfigName": {"Ref": "ConfigName"},
                        "ProductionVariants": [
                            {
                                "VariantName": variant_name,
                                "ModelName": {"Ref": "ModelName"},
                                "InitialInstanceCount": 1,
                                "InstanceType": "ml.m5.large",
                            }
                        ],
                        "Tags": [{"Key": "sim2real", "Value": CHECK}],
                    },
                    "DependsOn": "Model",
                },
                "Endpoint": {
                    "Type": "AWS::SageMaker::Endpoint",
                    "Properties": {
                        "EndpointName": {"Ref": "EndpointName"},
                        "EndpointConfigName": {"Ref": "ConfigName"},
                        "Tags": [{"Key": "sim2real", "Value": CHECK}],
                    },
                    "DependsOn": "EndpointConfig",
                },
            },
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "ModelName", "ParameterValue": model_name},
            {"ParameterKey": "ConfigName", "ParameterValue": config_name},
            {"ParameterKey": "EndpointName", "ParameterValue": endpoint_name},
            {"ParameterKey": "RoleArn", "ParameterValue": role_arn},
            {"ParameterKey": "Image", "ParameterValue": image_uri},
            {"ParameterKey": "ModelDataUrl", "ParameterValue": model_data_url},
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _wait_for_stack_status(
        ctx,
        stack_name,
        success_statuses={"CREATE_COMPLETE"},
        failure_statuses={"CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_IN_PROGRESS"},
        timeout_s=1200,
    )

    endpoint = _poll_until(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        lambda d: d["EndpointStatus"] in ("InService", "Failed"),
        timeout_s=900,
        interval_s=15,
    )
    assert endpoint["EndpointStatus"] == "InService", (
        f"endpoint ended in {endpoint['EndpointStatus']}: {endpoint.get('FailureReason')}"
    )
    assert endpoint["EndpointConfigName"] == config_name, (
        f"expected DescribeEndpoint to reflect config {config_name!r}, "
        f"got {endpoint['EndpointConfigName']!r}"
    )

    variant = endpoint["ProductionVariants"][0]
    assert variant["VariantName"] == variant_name, (
        f"expected variant name {variant_name!r}, got {variant['VariantName']!r}"
    )
    assert variant["CurrentInstanceCount"] == 1, (
        f"expected CurrentInstanceCount 1, got {variant['CurrentInstanceCount']!r}"
    )
    assert variant["DesiredInstanceCount"] == 1, (
        f"expected DesiredInstanceCount 1, got {variant['DesiredInstanceCount']!r}"
    )

    endpoint_config = sm.describe_endpoint_config(EndpointConfigName=config_name)
    ec_variant = endpoint_config["ProductionVariants"][0]
    assert ec_variant["ModelName"] == model_name, (
        f"expected EndpointConfig's variant to reference model {model_name!r}, "
        f"got {ec_variant['ModelName']!r}"
    )
    assert ec_variant["InitialInstanceCount"] == 1, (
        f"expected InitialInstanceCount 1, got {ec_variant['InitialInstanceCount']!r}"
    )
    assert ec_variant["InstanceType"] == "ml.m5.large", (
        f"expected InstanceType 'ml.m5.large', got {ec_variant['InstanceType']!r}"
    )

    model = sm.describe_model(ModelName=model_name)
    assert model["ExecutionRoleArn"] == role_arn, (
        f"expected DescribeModel ExecutionRoleArn {role_arn!r}, got {model['ExecutionRoleArn']!r}"
    )
    assert model["PrimaryContainer"]["ModelDataUrl"] == model_data_url, (
        f"expected PrimaryContainer.ModelDataUrl {model_data_url!r}, "
        f"got {model['PrimaryContainer']['ModelDataUrl']!r}"
    )
    assert model["PrimaryContainer"]["Image"].split("@")[0] == image_uri.split("@")[0], (
        f"expected PrimaryContainer.Image {image_uri!r} (digest suffix aside), "
        f"got {model['PrimaryContainer']['Image']!r}"
    )

    # UpdateEndpoint must verify the referenced EndpointConfig exists.
    bogus_config_name = ctx.unique_name("sim2real-sm-ep-config-missing-")
    try:
        sm.update_endpoint(EndpointName=endpoint_name, EndpointConfigName=bogus_config_name)
        raise AssertionError(
            "UpdateEndpoint with a nonexistent EndpointConfigName unexpectedly succeeded"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message", "")
        assert code == "ValidationException", (
            f"expected ValidationException for nonexistent endpoint config, got {code}: {message}"
        )
        expected = f'Could not find endpoint configuration "{bogus_config_name}".'
        assert message == expected, f"expected message {expected!r}, got {message!r}"


#: Per-region ECR registry accounts of the built-in linear-learner image (they differ from the
#: XGBoost ones), as listed in the `sagemaker` SDK's image_uri_config/linear-learner.json.
_LINEAR_LEARNER_REGISTRY_ACCOUNTS = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-south-1": "991648021394",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "712309505854",
    "ca-central-1": "469771592824",
    "eu-central-1": "664544806723",
    "eu-north-1": "669576153137",
    "eu-west-1": "438346466558",
    "eu-west-2": "644912444149",
    "eu-west-3": "749696950732",
    "sa-east-1": "855470959533",
}


def _linear_learner_image_uri(region: str) -> str:
    account = _LINEAR_LEARNER_REGISTRY_ACCOUNTS.get(region)
    if account is None:
        raise AssertionError(
            f"no SageMaker built-in linear-learner ECR registry account mapped for region "
            f"{region!r} - add it from the SDK's image_uri_config/linear-learner.json"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:1"


def _tiny_binary_classification_csv() -> str:
    rows = []
    for i in range(40):
        label = i % 2
        f1 = 1.0 + label * 3.0 + (i % 3) * 0.05
        f2 = 0.5 - label * 2.0 + (i % 5) * 0.02
        rows.append(f"{label},{f1:.3f},{f2:.3f}")
    return "\n".join(rows) + "\n"


def _create_bucket(ctx, s3, bucket: str) -> None:
    # us-east-1 is the one region the S3 API rejects an explicit LocationConstraint for;
    # this branches on ctx.region, not a hardcoded assumption of which region we're in.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, bucket))


def _empty_and_delete_bucket(ctx, s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_training_job_with_role_retry(sm, *, timeout_s: float = 120.0, interval_s: float = 10.0, **kwargs) -> None:
    """Retry CreateTrainingJob only on the role-propagation ValidationException, bounded by
    timeout_s; any other failure raises immediately."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.create_training_job(**kwargs)
            return
        except ClientError as exc:
            message = str(exc).lower()
            # AWS words the propagation race as "Could not assume role arn:aws:iam::...".
            role_not_yet_usable = exc.response["Error"]["Code"] == "ValidationException" and (
                "not authorized" in message
                or "cannot be assumed" in message
                or "could not assume role" in message
                or "is invalid" in message
            )
            if not role_not_yet_usable or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _wait_for_stack_status(
    ctx,
    stack_name: str,
    *,
    success_statuses: set[str],
    failure_statuses: set[str],
    timeout_s: float = 600,
    interval_s: float = 10,
) -> str:
    cfn = ctx.client("cloudformation")

    def _status() -> str:
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]

    deadline = time.monotonic() + timeout_s
    status = _status()
    while time.monotonic() < deadline:
        status = _status()
        if status in success_statuses:
            return status
        if status in failure_statuses:
            raise AssertionError(f"stack {stack_name} entered failure status {status}")
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not reach {success_statuses} within {timeout_s}s "
        f"(last status: {status})"
    )


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
