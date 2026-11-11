"""cfn-deploy-sagemaker-execution-role-trust-policy-positive."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sagemaker-execution-role-trust-policy-positive"
GROUP = "iam-trust"
SERVICES = ["s3", "sagemaker"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  RoleName:
    Type: String
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
  ExecRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Ref RoleName
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: s3-scoped-access
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:PutObject
                  - s3:ListBucket
                Resource:
                  - !GetAtt DataBucket.Arn
                  - !Sub '${DataBucket.Arn}/*'
        - PolicyName: logs-and-ecr
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                  - ecr:GetAuthorizationToken
                  - ecr:BatchCheckLayerAvailability
                  - ecr:GetDownloadUrlForLayer
                  - ecr:BatchGetImage
                Resource: '*'
Outputs:
  BucketName:
    Value: !Ref DataBucket
  RoleArn:
    Value: !GetAtt ExecRole.Arn
"""

_LINEAR_LEARNER_ACCOUNT_BY_REGION = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-south-1": "720646828776",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ca-central-1": "469771592824",
    "eu-central-1": "664544806723",
    "eu-west-1": "438346466558",
    "eu-west-2": "644912444149",
    "sa-east-1": "855470959533",
}


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A role whose AssumeRolePolicyDocument trusts sagemaker.amazonaws.com is genuinely usable:
    CreateTrainingJob (which makes SageMaker assume the role immediately) accepts it and the job
    progresses instead of failing on a trust error."""
    image = _linear_learner_image(ctx.region)
    role_name = _xname(ctx, "trustrole")
    result = _deploy_cfn(
        ctx, _TEMPLATE, parameters={"RoleName": role_name}, timeout_s=180.0
    )
    bucket = result["outputs"]["BucketName"]
    role_arn = result["outputs"]["RoleArn"]

    iam = ctx.client("iam")
    trust_doc = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    principals = [
        s["Principal"].get("Service")
        for s in trust_doc["Statement"]
        if s["Effect"] == "Allow"
    ]
    assert "sagemaker.amazonaws.com" in principals, principals

    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="train/train.csv", Body=_tiny_binary_csv())
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    sm = ctx.client("sagemaker")
    job_name = _xname(ctx, "trustjob")
    sm.create_training_job(
        TrainingJobName=job_name,
        AlgorithmSpecification={"TrainingImage": image, "TrainingInputMode": "File"},
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
        ResourceConfig={
            "InstanceType": "ml.m5.large",
            "InstanceCount": 1,
            "VolumeSizeInGB": 5,
        },
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        HyperParameters={
            "predictor_type": "binary_classifier",
            "feature_dim": "2",
            "mini_batch_size": "8",
        },
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _safe_stop_training_job(ctx, job_name))

    # A broken trust relationship fails the CreateTrainingJob call itself, synchronously, before
    # any instance is provisioned. Reaching a non-terminal in-progress state (or completing
    # outright) proves SageMaker successfully assumed this role.
    status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
    assert status != "Failed", status

    sm.stop_training_job(TrainingJobName=job_name)
    final = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"],
        lambda s: s in {"Stopped", "Completed", "Failed"},
        timeout_s=300.0,
        interval_s=10.0,
        description=f"training job {job_name} terminal",
    )
    assert final != "Failed", sm.describe_training_job(TrainingJobName=job_name).get(
        "FailureReason"
    )


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _linear_learner_image(region: str) -> str:
    account = _LINEAR_LEARNER_ACCOUNT_BY_REGION.get(region)
    if not account:
        raise AssertionError(
            f"no hardcoded linear-learner built-in-algorithm ECR account for region {region!r}"
        )
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:1"


def _tiny_binary_csv() -> bytes:
    rows = []
    for i in range(20):
        label = i % 2
        f1 = 0.1 + 0.01 * i if label else 0.9 - 0.01 * i
        f2 = 0.2 + 0.01 * i if label else 0.8 - 0.01 * i
        rows.append(f"{label},{f1:.3f},{f2:.3f}")
    return ("\n".join(rows) + "\n").encode("utf-8")


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    to_delete = []
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            to_delete.append({"Key": obj["Key"]})
    for i in range(0, len(to_delete), 1000):
        chunk = to_delete[i : i + 1000]
        if chunk:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": chunk})


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(s in msg for s in ("not found", "does not exist", "could not find"))
    )


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
        except ClientError as exc:
            # A job that has left InProgress refuses the stop with ValidationException; anything else fails.
            if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
                raise


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


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
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
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
