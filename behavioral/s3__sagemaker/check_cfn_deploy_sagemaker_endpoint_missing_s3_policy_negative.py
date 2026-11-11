"""cfn-deploy-sagemaker-endpoint-missing-s3-policy-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-deploy-sagemaker-endpoint-missing-s3-policy-negative"
GROUP = "overly-permissive"
SERVICES = ["s3", "sagemaker"]

# The stack holds only the two roles (identical except for S3 access). A failing
# AWS::SageMaker::Endpoint in the template would roll back the whole stack, so the
# Model/EndpointConfig/Endpoint are created via the SDK against these roles.
_ROLES_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  BucketName:
    Type: String
Resources:
  RoleWithS3:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: FullAccess
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:PutObject
                  - s3:ListBucket
                Resource:
                  - !Sub "arn:aws:s3:::${BucketName}"
                  - !Sub "arn:aws:s3:::${BucketName}/*"
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: !Sub "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:*"
  RoleWithoutS3:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: LogsOnly
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: !Sub "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:*"
Outputs:
  RoleWithS3Arn:
    Value: !GetAtt RoleWithS3.Arn
  RoleWithoutS3Arn:
    Value: !GetAtt RoleWithoutS3.Arn
"""

_LINEAR_LEARNER_ACCOUNTS = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "712309505854",
    "ap-south-1": "991648021394",
    "eu-west-1": "438346466558",
    "eu-west-2": "644912444149",
    "eu-central-1": "664544806723",
    "ca-central-1": "469771592824",
    "sa-east-1": "855470959533",
}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateModel with a role lacking S3 read on ModelDataUrl fails with the exact
    ValidationException and creates no model; with S3 read the same artifact reaches InService,
    and granting the role S3 read makes the identical CreateModel succeed."""
    bucket = _create_bucket(ctx)
    result = _deploy_cfn(ctx, _ROLES_TEMPLATE, parameters={"BucketName": bucket})
    role_ok = result["outputs"]["RoleWithS3Arn"]
    role_bad = result["outputs"]["RoleWithoutS3Arn"]

    # Both attempts use this same artifact, so the only variable is the role that fetches it.
    training = _run_linear_learner_training_job(ctx, role_arn=role_ok, bucket=bucket)
    assert training["TrainingJobStatus"] == "Completed", training.get("FailureReason")
    model_data_url = training["ModelArtifacts"]["S3ModelArtifacts"]
    image = _linear_learner_image(ctx.region)

    sm = ctx.client("sagemaker")

    model_ok = _xname(ctx, "model-ok")
    sm.create_model(
        ModelName=model_ok,
        ExecutionRoleArn=role_ok,
        PrimaryContainer={"Image": image, "ModelDataUrl": model_data_url},
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_ok))

    config_ok = _xname(ctx, "epc-ok")
    sm.create_endpoint_config(
        EndpointConfigName=config_ok,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_ok,
                "InstanceType": "ml.m5.large",
                "InitialInstanceCount": 1,
            }
        ],
    )
    ctx.on_cleanup(lambda: sm.delete_endpoint_config(EndpointConfigName=config_ok))

    endpoint_ok = _xname(ctx, "ep-ok")
    sm.create_endpoint(EndpointName=endpoint_ok, EndpointConfigName=config_ok)
    ctx.on_cleanup(lambda: sm.delete_endpoint(EndpointName=endpoint_ok))

    described_ok = _poll_until(
        lambda: sm.describe_endpoint(EndpointName=endpoint_ok),
        lambda r: r["EndpointStatus"] in {"InService", "Failed"},
        timeout_s=900.0,
        interval_s=20.0,
        description=f"endpoint {endpoint_ok}",
    )
    assert described_ok["EndpointStatus"] == "InService", described_ok.get("FailureReason")

    # CreateModel itself validates that the execution role can read ModelDataUrl.
    model_bad = _xname(ctx, "model-bad")
    try:
        sm.create_model(
            ModelName=model_bad,
            ExecutionRoleArn=role_bad,
            PrimaryContainer={"Image": image, "ModelDataUrl": model_data_url},
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ValidationException", (
            f"expected ValidationException for a role with no S3 read access to "
            f"{model_data_url!r}, got {code!r}: {exc}"
        )
        expected_message = (
            f'Could not access model data at {model_data_url}. Please ensure that the role "{role_bad}" '
            'exists and that its trust relationship policy allows the action "sts:AssumeRole" for the '
            'service principal "sagemaker.amazonaws.com". Also ensure that the role has '
            f'"s3:GetObject" permissions and that the object is located in {ctx.region}. If your '
            "Model uses multiple models or uncompressed models, please ensure that the role has "
            '"s3:ListBucket" permission.'
        )
        assert exc.response["Error"]["Message"] == expected_message, (
            f"expected the S3-access failure reason naming the inaccessible model data "
            f"in the message, got: {exc}"
        )
    else:
        ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_bad))
        raise AssertionError(
            "CreateModel with a role lacking S3 read access unexpectedly succeeded"
        )

    listed = sm.list_models(NameContains=model_bad)["Models"]
    listed_names = {m["ModelName"] for m in listed}
    assert model_bad not in listed_names, (
        f"CreateModel raised ValidationException for {model_bad!r} but ListModels "
        f"still shows it: {listed_names}"
    )

    # Restore via a direct IAM call rather than a stack update; the retry poll below covers
    # IAM propagation.
    iam = ctx.client("iam")
    role_bad_name = role_bad.rsplit("/", 1)[-1]
    iam.put_role_policy(
        RoleName=role_bad_name,
        PolicyName="restored-s3-access",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }],
        }),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_bad_name, PolicyName="restored-s3-access")
    )

    def _attempt_restored_create() -> dict[str, Any] | None:
        try:
            return sm.create_model(
                ModelName=model_bad,
                ExecutionRoleArn=role_bad,
                PrimaryContainer={"Image": image, "ModelDataUrl": model_data_url},
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationException" and (
                "Could not access model data" in str(exc)
            ):
                return None
            raise

    restored = _poll_until(
        _attempt_restored_create,
        lambda r: r is not None,
        timeout_s=60.0,
        interval_s=10.0,
        description=f"CreateModel for {model_bad} after restoring S3 access to its role",
    )
    ctx.on_cleanup(lambda: sm.delete_model(ModelName=model_bad))
    assert restored.get("ModelArn"), (
        f"restored CreateModel for {model_bad!r} succeeded but returned no ModelArn: {restored}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, "bkt")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _linear_learner_image(region: str) -> str:
    account = _LINEAR_LEARNER_ACCOUNTS.get(region)
    if account is None:
        raise AssertionError(
            f"no known built-in linear-learner ECR registry account for region {region!r}; "
            "would need the SageMaker Python SDK's image_uris.retrieve to resolve this "
            "dynamically for arbitrary regions"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:1"


def _linear_learner_csv_rows(n: int = 40) -> bytes:
    lines = []
    for i in range(n):
        label = i % 2
        if label == 0:
            f1, f2 = 0.10 + 0.05 * i, 0.20 + 0.03 * i
        else:
            f1, f2 = 5.00 + 0.05 * i, 5.20 + 0.03 * i
        lines.append(f"{label},{f1:.4f},{f2:.4f}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def _run_linear_learner_training_job(ctx, *, role_arn: str, bucket: str, timeout_s: float = 900.0) -> dict[str, Any]:
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    job_name = _xname(ctx, "train")
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=_linear_learner_csv_rows())
    sm.create_training_job(
        TrainingJobName=job_name,
        AlgorithmSpecification={
            "TrainingImage": _linear_learner_image(ctx.region),
            "TrainingInputMode": "File",
        },
        RoleArn=role_arn,
        InputDataConfig=[
            {
                "ChannelName": "train",
                "DataSource": {
                    "S3DataSource": {
                        "S3DataType": "S3Prefix",
                        "S3Uri": f"s3://{bucket}/train/",
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
                "ContentType": "text/csv",
            }
        ],
        OutputDataConfig={"S3OutputPath": f"s3://{bucket}/output/"},
        ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 5},
        StoppingCondition={"MaxRuntimeInSeconds": int(timeout_s)},
        HyperParameters={
            "predictor_type": "binary_classifier",
            "mini_batch_size": "8",
            "epochs": "3",
        },
    )
    return _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=job_name),
        lambda r: r["TrainingJobStatus"] in {"Completed", "Failed", "Stopped"},
        timeout_s=timeout_s,
        interval_s=15.0,
        description=f"training job {job_name}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
