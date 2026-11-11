"""deploy-stack-outputs-correct-codebuild-project-arn-in-pipeline-stage."""
from __future__ import annotations

import io
import time
import zipfile
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-stack-outputs-correct-codebuild-project-arn-in-pipeline-stage"
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
  ProjectArn:
    Value: !GetAtt CodeBuildProject.Arn
"""


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The pipeline's Build stage action configuration names the exact CodeBuild project
    whose ARN matches the stack's ProjectArn output — no drift between the wiring and the
    resource actually created."""
    bucket = _create_source_bucket(ctx)
    key = "source.zip"
    _upload_zip_source(ctx, bucket, key, {"readme.txt": "wiring-check source\n"})

    result = _deploy_cfn(
        ctx,
        _TEMPLATE,
        parameters={"SourceBucketName": bucket, "SourceObjectKey": key},
        timeout_s=300.0,
    )
    outputs = result["outputs"]
    pipeline_name = outputs["PipelineName"]
    expected_project_arn = outputs["ProjectArn"]

    cp = ctx.client("codepipeline")
    pipeline = cp.get_pipeline(name=pipeline_name)["pipeline"]
    build_stage = next(s for s in pipeline["stages"] if s["name"] == "Build")
    build_action = next(a for a in build_stage["actions"] if a["name"] == "Build")
    configured_project_name = build_action["configuration"]["ProjectName"]

    codebuild = ctx.client("codebuild")
    project = codebuild.batch_get_projects(names=[configured_project_name])["projects"][0]
    assert project["arn"] == expected_project_arn, (
        f"pipeline stage references project {configured_project_name!r} whose ARN "
        f"{project['arn']!r} does not match the stack output {expected_project_arn!r}"
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
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
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


def _create_source_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, "src")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _upload_zip_source(ctx, bucket: str, key: str, files: dict[str, str]) -> None:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files.items():
            zf.writestr(fname, content)
    ctx.client("s3").put_object(Bucket=bucket, Key=key, Body=buf.getvalue())


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
