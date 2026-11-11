"""deploy-cfn-stack-pipeline-codebuild-ecr-full-integration."""
from __future__ import annotations

import io
import time
import zipfile
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-stack-pipeline-codebuild-ecr-full-integration"
GROUP = "deploy-wiring"
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
  Repository:
    Type: AWS::ECR::Repository
    Properties:
      ImageTagMutability: MUTABLE
      EmptyOnDelete: true
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
              - Effect: Allow
                Action:
                  - ecr:GetAuthorizationToken
                Resource: "*"
              - Effect: Allow
                Action:
                  - ecr:BatchCheckLayerAvailability
                  - ecr:PutImage
                  - ecr:InitiateLayerUpload
                  - ecr:UploadLayerPart
                  - ecr:CompleteLayerUpload
                  - ecr:BatchGetImage
                  - ecr:GetDownloadUrlForLayer
                Resource: !GetAtt Repository.Arn
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
            pre_build:
              commands:
                - aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $REPO_URI
            build:
              commands:
                - docker build -t $REPO_URI:latest .
            post_build:
              commands:
                - docker push $REPO_URI:latest
      Environment:
        Type: LINUX_CONTAINER
        ComputeType: BUILD_GENERAL1_SMALL
        Image: aws/codebuild/standard:7.0
        PrivilegedMode: true
        EnvironmentVariables:
          - Name: REPO_URI
            Value: !GetAtt Repository.RepositoryUri
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
              OutputArtifacts:
                - Name: BuildOutput
Outputs:
  PipelineName:
    Value: !Ref Pipeline
  ProjectArn:
    Value: !GetAtt CodeBuildProject.Arn
  RepositoryUri:
    Value: !GetAtt Repository.RepositoryUri
  RepositoryName:
    Value: !Ref Repository
  ArtifactBucketName:
    Value: !Ref ArtifactBucket
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """Deploy CodePipeline+CodeBuild+ECR via CloudFormation; a real pipeline execution
    must actually build and push a Docker image to the ECR repository."""
    bucket = _create_source_bucket(ctx)
    key = "source.zip"
    _upload_zip_source(
        ctx,
        bucket,
        key,
        {
            "Dockerfile": (
                "FROM public.ecr.aws/docker/library/alpine:3.19\nCMD [\"true\"]\n"
            )
        },
    )

    result = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={"SourceBucketName": bucket, "SourceObjectKey": key},
        timeout_s=300.0,
    )
    outputs = result["outputs"]
    pipeline_name = outputs["PipelineName"]
    repo_name = outputs["RepositoryName"]
    artifact_bucket = outputs["ArtifactBucketName"]
    # CodePipeline writes SourceOutput/BuildOutput artifacts into this CFN-managed bucket during
    # execution, and CloudFormation cannot delete a non-empty S3 bucket, so the stack delete (already
    # registered by _deploy_cfn) would DELETE_FAILED without this. Registered after, so LIFO runs it
    # first.
    ctx.on_cleanup(lambda: _empty_bucket(ctx, artifact_bucket))

    cp = ctx.client("codepipeline")
    execution_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]

    final_status = _wait_pipeline_execution(ctx, pipeline_name, execution_id, timeout_s=900.0)
    assert final_status == "Succeeded", f"pipeline execution ended in {final_status}"

    ecr = ctx.client("ecr")
    images = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": "latest"}])
    detail = images["imageDetails"][0]
    assert detail["imageSizeInBytes"] > 0
    assert "imagePushedAt" in detail


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


def _stack_missing(exc: ClientError) -> bool:
    err = exc.response.get("Error", {})
    return err.get("Code") == "ValidationError" and "does not exist" in err.get("Message", "")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
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


def _empty_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    try:
        versions = s3.list_object_versions(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchBucket":
            return
        raise
    objs = [
        {"Key": v["Key"], "VersionId": v["VersionId"]}
        for v in versions.get("Versions", []) + versions.get("DeleteMarkers", [])
    ]
    if objs:
        s3.delete_objects(Bucket=name, Delete={"Objects": objs})


def _upload_zip_source(ctx, bucket: str, key: str, files: dict[str, str]) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files.items():
            zf.writestr(fname, content)
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=buf.getvalue())


def _wait_pipeline_execution(ctx, pipeline_name: str, execution_id: str, timeout_s: float = 900.0) -> str:
    cp = ctx.client("codepipeline")

    def _status():
        try:
            return cp.get_pipeline_execution(
                pipelineName=pipeline_name, pipelineExecutionId=execution_id
            )["pipelineExecution"]["status"]
        except ClientError as e:
            # StartPipelineExecution's response can be visible to GetPipelineExecution only after a
            # short propagation delay; treat that as not-yet-terminal, not a failure.
            if e.response.get("Error", {}).get("Code") == "PipelineExecutionNotFoundException":
                return "Pending"
            raise

    return _poll_until(
        _status,
        lambda s: s in {"Succeeded", "Failed", "Superseded", "Stopped", "Cancelled"},
        timeout_s=timeout_s,
        interval_s=15.0,
        description="pipeline execution terminal state",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
