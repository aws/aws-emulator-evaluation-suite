"""deploy-stack-pipeline-role-trust-policy-allows-codepipeline-service."""
from __future__ import annotations

import io
import time
import zipfile
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-stack-pipeline-role-trust-policy-allows-codepipeline-service"
GROUP = "iam-trust"
SERVICES = ["codebuild", "codepipeline", "ecr"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  SourceBucketName:
    Type: String
  SourceObjectKey:
    Type: String
Resources:
  ArtifactBucket:
    Type: AWS::S3::Bucket
  CodeBuildRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: codebuild.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: CodeBuildPolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - logs:CreateLogGroup
                  - logs:CreateLogStream
                  - logs:PutLogEvents
                Resource: "*"
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:GetObjectVersion
                  - s3:PutObject
                Resource:
                  - !Sub "${ArtifactBucket.Arn}/*"
                  - !Sub "arn:aws:s3:::${SourceBucketName}/*"
  CodeBuildProject:
    Type: AWS::CodeBuild::Project
    Properties:
      ServiceRole: !GetAtt CodeBuildRole.Arn
      Artifacts:
        Type: CODEPIPELINE
      Source:
        Type: CODEPIPELINE
        BuildSpec: |
          version: 0.2
          phases:
            build:
              commands:
                - echo "build executed" > output.txt
          artifacts:
            files:
              - output.txt
      Environment:
        Type: LINUX_CONTAINER
        ComputeType: BUILD_GENERAL1_SMALL
        Image: aws/codebuild/amazonlinux2-x86_64-standard:5.0
  PipelineRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: codepipeline.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: PipelinePolicy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:GetObjectVersion
                  - s3:GetBucketVersioning
                  - s3:GetBucketAcl
                  - s3:GetBucketLocation
                  - s3:GetObjectTagging
                  - s3:GetObjectVersionTagging
                  - s3:PutObject
                Resource:
                  - !GetAtt ArtifactBucket.Arn
                  - !Sub "${ArtifactBucket.Arn}/*"
                  - !Sub "arn:aws:s3:::${SourceBucketName}"
                  - !Sub "arn:aws:s3:::${SourceBucketName}/*"
              - Effect: Allow
                Action:
                  - codebuild:BatchGetBuilds
                  - codebuild:StartBuild
                Resource: !GetAtt CodeBuildProject.Arn
  Pipeline:
    Type: AWS::CodePipeline::Pipeline
    Properties:
      RoleArn: !GetAtt PipelineRole.Arn
      ArtifactStore:
        Type: S3
        Location: !Ref ArtifactBucket
      Stages:
        - Name: Source
          Actions:
            - Name: Source
              ActionTypeId:
                Category: Source
                Owner: AWS
                Provider: S3
                Version: '1'
              Configuration:
                S3Bucket: !Ref SourceBucketName
                S3ObjectKey: !Ref SourceObjectKey
                PollForSourceChanges: 'false'
              OutputArtifacts:
                - Name: SourceOutput
        - Name: Build
          Actions:
            - Name: Build
              ActionTypeId:
                Category: Build
                Owner: AWS
                Provider: CodeBuild
                Version: '1'
              Configuration:
                ProjectName: !Ref CodeBuildProject
              InputArtifacts:
                - Name: SourceOutput
Outputs:
  PipelineName:
    Value: !Ref Pipeline
  PipelineRoleArn:
    Value: !GetAtt PipelineRole.Arn
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """The deployed CodePipeline service role trusts codepipeline.amazonaws.com, and that
    trust is what actually lets CodePipeline assume the role and drive a stage execution."""
    bucket = _create_source_bucket(ctx)
    key = "source.zip"
    _upload_zip_source(ctx, bucket, key, {"readme.txt": "trust-check source\n"})

    result = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={"SourceBucketName": bucket, "SourceObjectKey": key},
        timeout_s=300.0,
    )
    outputs = result["outputs"]
    pipeline_name = outputs["PipelineName"]
    role_arn = outputs["PipelineRoleArn"]
    role_name = role_arn.split("/")[-1]

    iam = ctx.client("iam")
    trust_doc = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    statements = trust_doc["Statement"]
    trusts_codepipeline = any(
        s.get("Effect") == "Allow"
        and s.get("Action") == "sts:AssumeRole"
        and s.get("Principal", {}).get("Service") == "codepipeline.amazonaws.com"
        for s in statements
    )
    assert trusts_codepipeline, f"role trust policy does not trust codepipeline.amazonaws.com: {statements}"

    # Functional proof: CodePipeline must actually be able to assume this role to drive
    # the stage execution (StartBuild on the CodeBuild project) end to end.
    ctx.client("codepipeline")
    final_status, detail = _run_pipeline_with_retry(ctx, pipeline_name, timeout_s=300.0)
    assert final_status == "Succeeded", f"pipeline execution ended in {final_status}: {detail}"


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


def _empty_stack_buckets(ctx, stack_name: str) -> None:
    """CloudFormation's AWS::S3::Bucket cannot delete a non-empty bucket, and a pipeline
    execution deposits artifacts into ArtifactBucket, so DeleteStack fails on it unless we
    empty it first."""
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    try:
        resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    except ClientError as exc:
        if _stack_missing(exc):
            return
        raise
    for r in resources:
        if r.get("ResourceType") != "AWS::S3::Bucket":
            continue
        bucket = r.get("PhysicalResourceId")
        if not bucket:
            continue
        try:
            versions = s3.list_object_versions(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchBucket":
                continue
            raise
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in versions.get("Versions", []) + versions.get("DeleteMarkers", [])
        ]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})


def _stack_missing(exc: ClientError) -> bool:
    err = exc.response.get("Error", {})
    return err.get("Code") == "ValidationError" and "does not exist" in err.get("Message", "")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    _empty_stack_buckets(ctx, stack_name)
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if _stack_missing(exc):
                return "GONE"
            raise

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=2.0,
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


def _create_source_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, "src")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    # CodePipeline's S3 source action requires the bucket to be versioned.
    s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup():
        versions = s3.list_object_versions(Bucket=name)
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in versions.get("Versions", []) + versions.get("DeleteMarkers", [])
        ]
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _upload_zip_source(ctx, bucket: str, key: str, files: dict[str, str]) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files.items():
            zf.writestr(fname, content)
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=buf.getvalue())


def _wait_pipeline_execution(ctx, pipeline_name: str, execution_id: str, timeout_s: float = 300.0) -> str:
    cp = ctx.client("codepipeline")

    def _status():
        try:
            return cp.get_pipeline_execution(
                pipelineName=pipeline_name, pipelineExecutionId=execution_id
            )["pipelineExecution"]["status"]
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "PipelineExecutionNotFoundException":
                # Execution record can lag briefly behind StartPipelineExecution's return.
                return "Pending"
            raise

    return _poll_until(
        _status,
        lambda s: s in {"Succeeded", "Failed", "Superseded", "Stopped", "Cancelled"},
        timeout_s=timeout_s,
        interval_s=10.0,
        description="pipeline execution terminal state",
    )


def _pipeline_failure_detail(ctx, pipeline_name: str, execution_id: str) -> str:
    cp = ctx.client("codepipeline")
    try:
        resp = cp.list_action_executions(
            pipelineName=pipeline_name,
            filter={"pipelineExecutionId": execution_id},
        )
        details = []
        for ae in resp.get("actionExecutionDetails", []):
            status = ae.get("status")
            if status not in (None, "Succeeded", "InProgress"):
                details.append(
                    f"{ae.get('stageName')}/{ae.get('actionName')}={status}: "
                    f"{ae.get('output', {}).get('executionResult', {}).get('externalExecutionSummary', '')}"
                )
        return "; ".join(details) or "no failing action execution details found"
    except ClientError as e:
        return f"could not fetch action execution details: {e}"


def _run_pipeline_with_retry(ctx, pipeline_name: str, timeout_s: float = 300.0, max_attempts: int = 3):
    """Start (or restart) a pipeline execution, retrying on failure to absorb IAM role
    propagation delay for freshly created service roles (create_role does not wait for the
    permissions to actually be usable by the trusted service)."""
    cp = ctx.client("codepipeline")
    last_status = None
    last_detail = None
    for attempt in range(max_attempts):
        execution_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
        status = _wait_pipeline_execution(ctx, pipeline_name, execution_id, timeout_s=timeout_s)
        if status == "Succeeded":
            return status, None
        last_status = status
        last_detail = _pipeline_failure_detail(ctx, pipeline_name, execution_id)
        time.sleep(15.0 * (attempt + 1))
    return last_status, last_detail


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
