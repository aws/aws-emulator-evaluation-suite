"""cfn-deploy-sagemaker-training-job-resource-s3-output-positive."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-deploy-sagemaker-training-job-resource-s3-output-positive"
GROUP = "deployment-order"
SERVICES = ["s3", "sagemaker"]

# AWS CloudFormation has no native `AWS::SageMaker::TrainingJob` resource type, so the "training
# job resource" the stack provisions is the IAM role and S3 access wiring a training job depends
# on (deployment-order: the role's trust + S3 policy must exist and be correct before SageMaker
# can write output there). The training job itself is started via the SDK using that stack output,
# which is the only way to actually observe the S3 write.
_TRAINING_ROLE_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  BucketName:
    Type: String
Resources:
  TrainingRole:
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
        - PolicyName: TrainingAccess
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
Outputs:
  RoleArn:
    Value: !GetAtt TrainingRole.Arn
"""

# Real, permanently fixed per-region AWS account IDs that host the built-in linear-learner
# algorithm container image; not a quota and not adjustable, so pinning them is correct.
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN stack provisions the IAM role a SageMaker training job depends on; a real training
    job started against that role writes its output artifact into the declared S3 bucket, and
    the artifact is actually present there after the job completes."""
    bucket = _create_bucket(ctx)
    result = _deploy_cfn(ctx, _TRAINING_ROLE_TEMPLATE, parameters={"BucketName": bucket})
    role_arn = result["outputs"]["RoleArn"]

    training = _run_linear_learner_training_job(ctx, role_arn=role_arn, bucket=bucket)
    assert training["TrainingJobStatus"] == "Completed", training.get("FailureReason")

    artifact_uri = training["ModelArtifacts"]["S3ModelArtifacts"]
    declared_prefix = f"s3://{bucket}/output/"
    assert artifact_uri.startswith(declared_prefix), artifact_uri

    artifact_key = artifact_uri[len(f"s3://{bucket}/"):]
    head = ctx.client("s3").head_object(Bucket=bucket, Key=artifact_key)
    assert head["ContentLength"] > 0, f"expected a non-empty model artifact at {artifact_uri}, got ContentLength={head['ContentLength']!r}"


# ===== helpers =====
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


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(s in msg for s in ("not found", "does not exist", "could not find"))
    )


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not _gone(exc):
                raise
            return "GONE"

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
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _safe_stop_training_job(ctx, job_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        desc = sm.describe_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        if not _gone(exc):
            raise
        return
    if desc["TrainingJobStatus"] in ("InProgress", "Stopping"):
        try:
            sm.stop_training_job(TrainingJobName=job_name)
        except ClientError as err:
            # A job that has left InProgress refuses the stop with ValidationException; anything else fails.
            if err.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
                raise


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
    ctx.on_cleanup(lambda: _safe_stop_training_job(ctx, job_name))
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
