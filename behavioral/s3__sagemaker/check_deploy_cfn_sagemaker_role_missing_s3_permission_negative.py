"""deploy-cfn-sagemaker-role-missing-s3-permission-negative."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-sagemaker-role-missing-s3-permission-negative"
GROUP = "overly-permissive"
SERVICES = ["s3", "sagemaker"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
  RoleNoPerm:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: sagemaker.amazonaws.com
            Action: sts:AssumeRole
  RoleWithPerm:
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
        - PolicyName: s3-access
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
  RoleNoPermArn:
    Value: !GetAtt RoleNoPerm.Arn
  RoleWithPermArn:
    Value: !GetAtt RoleWithPerm.Arn
"""

# AWS-published per-region account ids that host the built-in linear-learner algorithm image;
# looked up by ctx.region below, so the check always trains against the image for the region it
# actually runs in rather than pinning to one.
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


def _make_training_job(sm, *, job_name, image, role_arn, bucket, output_prefix):
    input_uri = f"s3://{bucket}/input/"
    output_uri = f"s3://{bucket}/{output_prefix}/"
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
    return output_uri


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c4",
    "cap:c7",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """CreateTrainingJob rejects a role with no S3 permissions on the training bucket upfront,
    creating no job and writing no output, while a sibling role with S3 permissions running the
    same job definition completes: the rejection is caused by the missing S3 permission."""
    image = _linear_learner_image(ctx.region)
    if image is None:
        raise AssertionError(
            f"no known linear-learner built-in algorithm ECR account for region {ctx.region}; "
            "add a mapping to close this gap for that region"
        )

    stack = _deploy_cfn(ctx, _TEMPLATE, timeout_s=180)
    bucket = stack["outputs"]["BucketName"]
    role_no_perm = stack["outputs"]["RoleNoPermArn"]
    role_with_perm = stack["outputs"]["RoleWithPermArn"]

    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="input/train.csv", Body=_training_csv())
    # The stack's own DELETE_COMPLETE needs the bucket empty first: CloudFormation cannot delete
    # an S3 bucket that still holds objects, and it does not know about objects this check wrote
    # outside the template. Registered after the stack's own cleanup (already queued inside
    # _deploy_cfn) so LIFO runs this first.
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket))

    sm = ctx.client("sagemaker")
    job_no_perm = ctx.unique_name("sim2real-xsvc-train-noperm-")
    job_with_perm = ctx.unique_name("sim2real-xsvc-train-perm-")

    # Negative: the role has no S3 permission at all, so CreateTrainingJob's own upfront
    # validation of the input channel rejects the request synchronously -- the job is never
    # created.
    try:
        _make_training_job(
            sm,
            job_name=job_no_perm,
            image=image,
            role_arn=role_no_perm,
            bucket=bucket,
            output_prefix=f"output-noperm/{job_no_perm}",
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"]["Message"]
        assert code == "ValidationException", (
            f"expected CreateTrainingJob to reject role {role_no_perm} (no S3 permission) with "
            f"ValidationException, got {code}: {message}"
        )
        assert message == _no_s3_objects_message(
            ctx, f"s3://{bucket}/input/", bucket, role_no_perm, list_denied=True
        ), f"expected the exact missing-s3:ListBucket rejection, got: {message}"
    else:
        raise AssertionError(
            f"expected CreateTrainingJob to reject role {role_no_perm} (no S3 permission) "
            "synchronously, but it was accepted"
        )

    # Effect absent, independent read: the rejected job was never created at all.
    try:
        sm.describe_training_job(TrainingJobName=job_no_perm)
    except ClientError as err:
        assert err.response["Error"]["Code"] == "ValidationException", (
            f"expected DescribeTrainingJob({job_no_perm}) to report it does not exist, got "
            f"{err.response['Error']['Code']}: {err.response['Error']['Message']}"
        )
        assert err.response["Error"]["Message"] == "Requested resource not found.", (
            err.response["Error"]
        )
    else:
        raise AssertionError(
            f"expected training job {job_no_perm} to not exist after CreateTrainingJob rejected "
            "it, but DescribeTrainingJob found it"
        )
    listing = s3.list_objects_v2(Bucket=bucket, Prefix=f"output-noperm/{job_no_perm}/")
    assert listing.get("KeyCount", 0) == 0, (
        f"expected no objects under output-noperm/{job_no_perm}/ (job was never created), found "
        f"{listing.get('KeyCount')} (keys: {[o['Key'] for o in listing.get('Contents', [])]})"
    )

    # Positive control: the same job definition, with a role that has S3 permission, is accepted
    # and completes.
    _make_training_job(
        sm,
        job_name=job_with_perm,
        image=image,
        role_arn=role_with_perm,
        bucket=bucket,
        output_prefix=f"output-perm/{job_with_perm}",
    )
    ctx.on_cleanup(lambda: _stop_job_safe(sm, job_with_perm))

    final_with_perm = _poll_until(
        lambda: sm.describe_training_job(TrainingJobName=job_with_perm),
        lambda d: d["TrainingJobStatus"] in {"Completed", "Failed", "Stopped"},
        timeout_s=1200.0,
        interval_s=20.0,
        description=f"training job {job_with_perm}",
    )
    assert final_with_perm["TrainingJobStatus"] == "Completed", (
        f"positive control expected training job {job_with_perm} to complete, got "
        f"{final_with_perm['TrainingJobStatus']}: {final_with_perm.get('FailureReason')}"
    )
    artifact_uri = final_with_perm["ModelArtifacts"]["S3ModelArtifacts"]
    _, _, artifact_key = artifact_uri.partition(f"s3://{bucket}/")
    s3.head_object(Bucket=bucket, Key=artifact_key)


def _gone(exc: ClientError) -> bool:
    """The error says the resource does not exist: never created, or already deleted."""
    err = exc.response["Error"]
    msg = err.get("Message", "").lower()
    return err["Code"] in ("ResourceNotFound", "NoSuchEntity", "NoSuchBucket") or (
        err["Code"] in ("ValidationException", "ValidationError")
        and any(s in msg for s in ("not found", "does not exist", "could not find"))
    )


def _stop_job_safe(sm, job_name: str) -> None:
    try:
        sm.stop_training_job(TrainingJobName=job_name)
    except ClientError as exc:
        # A job that has left InProgress refuses the stop with ValidationException; anything else fails.
        if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"] == "InProgress":
            raise


def _empty_bucket(s3, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})


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


def _no_s3_objects_message(ctx, s3_uri: str, bucket: str, role_arn: str, *, list_denied: bool) -> str:
    """SageMaker's exact refusal when an input channel's S3 prefix lists no objects for the role."""
    message = (
        f'No S3 objects found under S3 URL "{s3_uri}" given in input data source. Please ensure '
        f"that the bucket exists in the selected region ({ctx.region}), that objects exist under "
        f'that S3 prefix, and that the role "{role_arn}" has "s3:ListBucket" permissions on '
        f'bucket "{bucket}".'
    )
    if list_denied:
        role_name = role_arn.rsplit("/", 1)[-1]
        message += (
            f" Error message from S3: User: arn:aws:sts::{ctx.account}:assumed-role/{role_name}/"
            f'SageMaker is not authorized to perform: s3:ListBucket on resource: "arn:aws:s3:::'
            f'{bucket}" because no identity-based policy allows the s3:ListBucket action'
        )
    return message

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
