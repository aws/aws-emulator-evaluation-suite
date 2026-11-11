"""deploy-stack-missing-ecr-repository-policy-blocks-codebuild-push."""
from __future__ import annotations

import io
import time
import zipfile
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-stack-missing-ecr-repository-policy-blocks-codebuild-push"
GROUP = "permission-boundary"
SERVICES = ["codebuild", "codepipeline", "ecr"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  SourceBucketName:
    Type: String
  SourceObjectKey:
    Type: String
Resources:
  RepoAllowed:
    Type: AWS::ECR::Repository
    Properties:
      ImageTagMutability: MUTABLE
      EmptyOnDelete: true
      RepositoryPolicyText:
        Version: '2012-10-17'
        Statement:
          - Sid: AllowCodeBuildPush
            Effect: Allow
            Principal:
              AWS: !GetAtt CodeBuildRole.Arn
            Action:
              - ecr:BatchCheckLayerAvailability
              - ecr:PutImage
              - ecr:InitiateLayerUpload
              - ecr:UploadLayerPart
              - ecr:CompleteLayerUpload
              - ecr:BatchGetImage
              - ecr:GetDownloadUrlForLayer
  RepoDenied:
    Type: AWS::ECR::Repository
    Properties:
      ImageTagMutability: MUTABLE
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
                Resource: !Sub "arn:aws:s3:::${SourceBucketName}/*"
              - Effect: Allow
                Action:
                  - ecr:GetAuthorizationToken
                Resource: "*"
  CodeBuildProject:
    Type: AWS::CodeBuild::Project
    Properties:
      ServiceRole: !GetAtt CodeBuildRole.Arn
      Artifacts:
        Type: NO_ARTIFACTS
      Source:
        Type: S3
        Location: !Sub "${SourceBucketName}/${SourceObjectKey}"
        BuildSpec: |
          version: 0.2
          phases:
            pre_build:
              commands:
                - aws ecr get-login-password --region $AWS_DEFAULT_REGION | docker login --username AWS --password-stdin $ALLOWED_URI
            build:
              commands:
                - docker build -t $ALLOWED_URI:latest .
                - docker tag $ALLOWED_URI:latest $DENIED_URI:latest
            post_build:
              commands:
                - docker push $ALLOWED_URI:latest
                - docker push $DENIED_URI:latest || echo "expected push failure to denied repo"
      Environment:
        Type: LINUX_CONTAINER
        ComputeType: BUILD_GENERAL1_SMALL
        Image: aws/codebuild/standard:7.0
        PrivilegedMode: true
        EnvironmentVariables:
          - Name: ALLOWED_URI
            Value: !GetAtt RepoAllowed.RepositoryUri
          - Name: DENIED_URI
            Value: !GetAtt RepoDenied.RepositoryUri
Outputs:
  ProjectName:
    Value: !Ref CodeBuildProject
  RepoAllowedName:
    Value: !Ref RepoAllowed
  RepoDeniedName:
    Value: !Ref RepoDenied
"""


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CodeBuild role with no IAM ecr push permissions can only push to a repository
    whose repository policy explicitly grants it; a repository with no such policy statement
    rejects the push (positive/negative control on the same underlying build)."""
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
    project_name = outputs["ProjectName"]
    repo_allowed = outputs["RepoAllowedName"]
    repo_denied = outputs["RepoDeniedName"]

    codebuild = ctx.client("codebuild")
    build_id = codebuild.start_build(projectName=project_name)["build"]["id"]
    final_status = _wait_build(ctx, build_id, timeout_s=900.0)
    assert final_status == "SUCCEEDED", f"build ended in {final_status} (buildspec should swallow the expected push failure)"

    ecr = ctx.client("ecr")

    # Positive control: the repo whose repository policy grants this role push access has the
    # pushed image.
    allowed_images = ecr.describe_images(repositoryName=repo_allowed, imageIds=[{"imageTag": "latest"}])
    allowed_detail = allowed_images["imageDetails"][0]
    assert allowed_detail["imageSizeInBytes"] > 0, (
        f"expected a real pushed image with nonzero size in {repo_allowed}, "
        f"got imageSizeInBytes={allowed_detail.get('imageSizeInBytes')!r}"
    )

    # Negative: the repo with no repository policy statement for this role never received the
    # image — the push was rejected, not silently skipped.
    code, message = _error(
        lambda: ecr.describe_images(repositoryName=repo_denied, imageIds=[{"imageTag": "latest"}])
    )
    assert code == "ImageNotFoundException", (
        f"expected the policy-less repo {repo_denied} to have never received the pushed image "
        f"(ImageNotFoundException), got error code {code!r}"
    )
    expected_message = (
        f"The image with imageId {{imageDigest:'null', imageTag:'latest'}} does not exist "
        f"within the repository with name '{repo_denied}' in the registry with id '{ctx.account}'"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        objs = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
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


def _wait_build(ctx, build_id: str, timeout_s: float = 900.0) -> str:
    codebuild = ctx.client("codebuild")

    def _status():
        return codebuild.batch_get_builds(ids=[build_id])["builds"][0]["buildStatus"]

    return _poll_until(
        _status,
        lambda s: s in {"SUCCEEDED", "FAILED", "FAULT", "TIMED_OUT", "STOPPED"},
        timeout_s=timeout_s,
        interval_s=15.0,
        description=f"build {build_id} terminal state",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
