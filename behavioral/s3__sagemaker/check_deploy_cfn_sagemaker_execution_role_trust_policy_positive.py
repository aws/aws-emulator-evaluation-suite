"""deploy-cfn-sagemaker-execution-role-trust-policy-positive."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-sagemaker-execution-role-trust-policy-positive"
GROUP = "iam-trust"
SERVICES = ["s3", "sagemaker"]

_SKLEARN_ECR_ACCOUNT_BY_REGION = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "af-south-1": "510948584623",
    "ap-east-1": "651117190479",
    "ap-northeast-1": "354813040037",
    "ap-northeast-2": "366743142698",
    "ap-northeast-3": "867004704886",
    "ap-south-1": "720646828776",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ca-central-1": "341280168497",
    "eu-central-1": "492215442770",
    "eu-north-1": "662702820516",
    "eu-west-1": "141502667606",
    "eu-west-2": "764974769150",
    "eu-west-3": "659782779980",
    "me-south-1": "801668240914",
    "sa-east-1": "737474898029",
}


def _processing_image_uri(ctx: Any) -> str:
    """Region-qualified ECR URI of the AWS-owned prebuilt scikit-learn container.

    CreateProcessingJob rejects public registries (e.g. public.ecr.aws); every account
    is granted cross-account pull access to this SageMaker-maintained image in-Region.
    """
    account = _SKLEARN_ECR_ACCOUNT_BY_REGION.get(ctx.region)
    if not account:
        raise AssertionError(
            f"no known SageMaker scikit-learn ECR account for region {ctx.region!r}"
        )
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-scikit-learn:1.2-1-cpu-py3"


_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Resources:
  DataBucket:
    Type: AWS::S3::Bucket
  ProcRole:
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
  RoleArn:
    Value: !GetAtt ProcRole.Arn
"""


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
    """A CFN-created role trusting sagemaker.amazonaws.com is assumed by SageMaker itself to run
    a ProcessingJob that reads from and writes to the stack's S3 bucket."""
    stack = _deploy_cfn(ctx, _TEMPLATE, timeout_s=180)
    bucket = stack["outputs"]["BucketName"]
    role_arn = stack["outputs"]["RoleArn"]

    s3 = ctx.client("s3")
    # DeleteStack fails (leaving the bucket and the whole stack behind) if the bucket it owns
    # is non-empty, so this check's own writes into it must be undone before stack teardown.
    # on_cleanup runs LIFO, so registering this after _deploy_cfn's own stack-delete cleanup
    # makes it run first.
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket))

    iam = ctx.client("iam")
    role_name = role_arn.split("/")[-1]
    trust_doc = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    services = [
        stmt["Principal"].get("Service")
        for stmt in trust_doc["Statement"]
        if isinstance(stmt.get("Principal"), dict)
    ]
    assert "sagemaker.amazonaws.com" in services, (
        f"CFN-created role {role_name}'s AssumeRolePolicyDocument does not trust "
        f"sagemaker.amazonaws.com (Service principals found: {services!r})"
    )

    body = b"trust-policy-round-trip"
    s3.put_object(Bucket=bucket, Key="input/hello.txt", Body=body)

    sm = ctx.client("sagemaker")
    job_name = ctx.unique_name("sim2real-xsvc-proc-")
    sm.create_processing_job(
        ProcessingJobName=job_name,
        RoleArn=role_arn,
        AppSpecification={
            "ImageUri": _processing_image_uri(ctx),
            "ContainerEntrypoint": [
                "/bin/sh",
                "-c",
                "cp -r /opt/ml/processing/input/. /opt/ml/processing/output/",
            ],
        },
        ProcessingResources={
            "ClusterConfig": {
                "InstanceCount": 1,
                "InstanceType": "ml.m5.large",
                "VolumeSizeInGB": 5,
            }
        },
        ProcessingInputs=[
            {
                "InputName": "input",
                "S3Input": {
                    "S3Uri": f"s3://{bucket}/input/",
                    "LocalPath": "/opt/ml/processing/input",
                    "S3DataType": "S3Prefix",
                    "S3InputMode": "File",
                    "S3DataDistributionType": "FullyReplicated",
                },
            }
        ],
        ProcessingOutputConfig={
            "Outputs": [
                {
                    "OutputName": "output",
                    "S3Output": {
                        "S3Uri": f"s3://{bucket}/output/",
                        "LocalPath": "/opt/ml/processing/output",
                        "S3UploadMode": "EndOfJob",
                    },
                }
            ]
        },
        StoppingCondition={"MaxRuntimeInSeconds": 600},
    )

    def _cleanup_job() -> None:
        try:
            sm.stop_processing_job(ProcessingJobName=job_name)
        except ClientError as exc:
            # A job that has left InProgress refuses the stop with ValidationException; anything else fails.
            if exc.response["Error"]["Code"] != "ValidationException" or sm.describe_processing_job(ProcessingJobName=job_name)[
                "ProcessingJobStatus"
            ] == "InProgress":
                raise

    ctx.on_cleanup(_cleanup_job)

    final = _poll_until(
        lambda: sm.describe_processing_job(ProcessingJobName=job_name),
        lambda d: d["ProcessingJobStatus"] in ("Completed", "Failed", "Stopped"),
        timeout_s=900,
        interval_s=15.0,
        description=f"processing job {job_name}",
    )
    assert final["ProcessingJobStatus"] == "Completed", (
        f"processing job {job_name} using the sagemaker-trusted role did not complete "
        f"(status={final['ProcessingJobStatus']!r}, exit_message={final.get('ExitMessage')!r})"
    )

    obj = s3.get_object(Bucket=bucket, Key="output/hello.txt")
    actual = obj["Body"].read()
    assert actual == body, (
        f"processing job {job_name} output/hello.txt body does not match the input "
        f"written by the test (expected {body!r}, got {actual!r}) -- the sagemaker-trusted "
        f"role did not actually round-trip bytes through S3"
    )


# ===== helpers =====

_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _empty_bucket(s3: Any, bucket: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})


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
