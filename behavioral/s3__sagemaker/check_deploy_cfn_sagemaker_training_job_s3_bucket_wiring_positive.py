"""deploy-cfn-sagemaker-training-job-s3-bucket-wiring-positive."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-sagemaker-training-job-s3-bucket-wiring-positive"
GROUP = "deployment-order"
SERVICES = ["s3", "sagemaker"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
  TrainRole:
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
        - PolicyName: s3-train-access
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
Outputs:
  BucketName:
    Value: !Ref DataBucket
  RoleArn:
    Value: !GetAtt TrainRole.Arn
"""

# Built-in "linear-learner" algorithm image account IDs (stable, long-documented SageMaker
# built-in algorithm ECR registry accounts). Region -> account id.
_LINEAR_LEARNER_ACCOUNTS = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "eu-west-1": "438346466558",
    "eu-west-2": "644912444149",
    "eu-west-3": "749696950732",
    "eu-central-1": "664544806723",
    "eu-north-1": "669576153137",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-south-1": "720646828776",
    "ca-central-1": "469771592824",
    "sa-east-1": "855470959533",
}


def _linear_learner_image(region: str) -> str | None:
    account = _LINEAR_LEARNER_ACCOUNTS.get(region)
    if account is None:
        return None
    return f"{account}.dkr.ecr.{region}.amazonaws.com/linear-learner:1"


def _training_csv() -> bytes:
    rows = []
    for i in range(20):
        label = float(i % 2)
        f1 = round(i * 0.05, 3)
        f2 = round((20 - i) * 0.03, 3)
        rows.append(f"{label},{f1},{f2}")
    return ("\n".join(rows) + "\n").encode("utf-8")


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A real SageMaker TrainingJob's InputDataConfig correctly resolves to the S3 bucket
    that was co-deployed via the same CFN stack: the job downloads training data from it,
    trains to completion, and writes the model artifact back into it."""
    image = _linear_learner_image(ctx.region)
    if image is None:
        raise AssertionError(
            f"no known linear-learner built-in algorithm ECR account for region {ctx.region}; "
            "add a mapping to close this gap for that region"
        )

    stack = _deploy_cfn(ctx, _TEMPLATE, timeout_s=180)
    bucket = stack["outputs"]["BucketName"]
    role_arn = stack["outputs"]["RoleArn"]

    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="input/train.csv", Body=_training_csv())
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    sm = ctx.client("sagemaker")
    job_name = ctx.unique_name("sim2real-xsvc-train-")
    input_uri = f"s3://{bucket}/input/"
    output_uri = f"s3://{bucket}/output/"
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
                        "S3Uri": input_uri,
                        "S3DataDistributionType": "FullyReplicated",
                    }
                },
                "ContentType": "text/csv",
            }
        ],
        OutputDataConfig={"S3OutputPath": output_uri},
        ResourceConfig={
            "InstanceType": "ml.m5.large",
            "InstanceCount": 1,
            "VolumeSizeInGB": 5,
        },
        StoppingCondition={"MaxRuntimeInSeconds": 900},
        HyperParameters={
            "predictor_type": "regressor",
            "feature_dim": "2",
            "mini_batch_size": "4",
            "epochs": "1",
        },
        Tags=_xsvc_tags_kv(),
    )

    ctx.on_cleanup(lambda: _best_effort_delete_training_job(ctx, job_name))
    ctx.on_cleanup(lambda: _safe_delete_trial_component(ctx, job_name))

    final = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=job_name),
        lambda d: d["TrainingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=1200,
        interval_s=20.0,
        description=f"training job {job_name}",
    )
    assert final["TrainingJobStatus"] == "Completed", final.get("FailureReason")
    assert (
        final["InputDataConfig"][0]["DataSource"]["S3DataSource"]["S3Uri"] == input_uri
    ), (
        f"expected the completed job to still report the co-deployed bucket's input URI "
        f"{input_uri!r}, got {final['InputDataConfig'][0]['DataSource']['S3DataSource']['S3Uri']!r}"
    )

    artifact_uri = final["ModelArtifacts"]["S3ModelArtifacts"]
    assert artifact_uri.startswith(output_uri), (
        f"expected model artifact {artifact_uri!r} to live under the co-deployed bucket's "
        f"output URI {output_uri!r}"
    )
    _, _, artifact_key = artifact_uri.partition(f"s3://{bucket}/")
    s3.head_object(Bucket=bucket, Key=artifact_key)


# ===== helpers =====

_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


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


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(s in msg for s in ("not found", "does not exist", "could not find"))
    )


def _best_effort_delete_training_job(ctx, job_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
        if status in ("InProgress", "Stopping"):
            sm.stop_training_job(TrainingJobName=job_name)
            _poll_until(
                lambda: sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"],
                lambda s: s not in ("InProgress", "Stopping"),
                timeout_s=300.0,
                interval_s=2.0,
                description=f"stop training job {job_name}",
            )
    except ClientError as exc:
        if not _gone(exc):
            raise
        return
    try:
        sm.delete_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        if not _gone(exc):
            raise


def _safe_delete_trial_component(ctx, job_name: str) -> None:
    # CreateTrainingJob auto-creates a same-lifetime "<job>-aws-training-job" trial component for
    # SageMaker Experiments tracking; DeleteTrainingJob does not remove it, so it is reclaimed here.
    sm = ctx.client("sagemaker")
    try:
        sm.delete_trial_component(TrialComponentName=f"{job_name}-aws-training-job")
    except ClientError as exc:
        if not _gone(exc):
            raise


def _empty_bucket(ctx, bucket: str) -> None:
    # CloudFormation's default DeletionPolicy (Delete) refuses to delete a non-empty S3 bucket,
    # which would leave both the bucket and the stack behind after the training job writes into
    # it -- so this empties it before the stack-delete cleanup (registered earlier, so it runs
    # after this one) runs.
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
