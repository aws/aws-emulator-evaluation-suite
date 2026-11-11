"""deploy-codepipeline-cloudformation-executes."""
from __future__ import annotations

import io
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-codepipeline-cloudformation-executes"
GROUP = "state-machine"
SERVICES = ["codepipeline"]

_TEMPLATE = """
AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  ProviderName:
    Type: String
  PipelineName:
    Type: String
Resources:
  ArtifactBucket:
    Type: AWS::S3::Bucket
    Properties:
      VersioningConfiguration:
        Status: Enabled
  PipelineRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal: {Service: codepipeline.amazonaws.com}
            Action: sts:AssumeRole
      Policies:
        - PolicyName: sim2real-inline
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - s3:GetObject
                  - s3:GetObjectVersion
                  - s3:PutObject
                  - s3:GetBucketVersioning
                  - s3:ListBucket
                Resource:
                  - !GetAtt ArtifactBucket.Arn
                  - !Sub '${ArtifactBucket.Arn}/*'
  CustomBuildActionType:
    Type: AWS::CodePipeline::CustomActionType
    Properties:
      Category: Build
      Provider: !Ref ProviderName
      Version: '1'
      InputArtifactDetails: {MaximumCount: 1, MinimumCount: 0}
      OutputArtifactDetails: {MaximumCount: 1, MinimumCount: 0}
  Pipeline:
    Type: AWS::CodePipeline::Pipeline
    DependsOn: CustomBuildActionType
    Properties:
      Name: !Ref PipelineName
      RoleArn: !GetAtt PipelineRole.Arn
      ArtifactStore:
        Type: S3
        Location: !Ref ArtifactBucket
      Stages:
        - Name: Source
          Actions:
            - Name: SourceAction
              ActionTypeId: {Category: Source, Owner: AWS, Provider: S3, Version: '1'}
              OutputArtifacts: [{Name: SourceOutput}]
              Configuration:
                S3Bucket: !Ref ArtifactBucket
                S3ObjectKey: source/source.zip
                PollForSourceChanges: 'false'
        - Name: Build
          Actions:
            - Name: BuildAction
              ActionTypeId: {Category: Build, Owner: Custom, Provider: !Ref ProviderName, Version: '1'}
              InputArtifacts: [{Name: SourceOutput}]
Outputs:
  BucketName:
    Value: !Ref ArtifactBucket
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipeline deployed by a CloudFormation stack reaches CREATE_COMPLETE, dispatches its Build job, and an
    execution started with StartPipelineExecution runs to Succeeded.
    """
    cfn = ctx.client("cloudformation")
    s3 = ctx.client("s3")
    cp = ctx.client("codepipeline")

    stack_name = ctx.unique_name("sim2real-cp-cfn-")
    provider = ("sim2realcfn" + stack_name[-20:]).replace("_", "-")[:35]
    pipeline_name = ctx.unique_name("sim2real-cp-cfnpipe-")

    def _cleanup_stack() -> None:
        bucket = _stack_output(ctx, stack_name, "BucketName")
        if bucket:
            _empty_bucket(ctx, bucket)
        cfn.delete_stack(StackName=stack_name)
        delete_status = _poll_until(
            lambda: _stack_status(ctx, stack_name),
            lambda st: st is None or st.endswith("COMPLETE") or st.endswith("FAILED"),
            timeout_s=300.0,
            interval_s=10.0,
        )
        assert delete_status is None or delete_status == "DELETE_COMPLETE", (
            f"stack teardown did not complete: {delete_status}"
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "ProviderName", "ParameterValue": provider},
            {"ParameterKey": "PipelineName", "ParameterValue": pipeline_name},
        ],
        Capabilities=["CAPABILITY_IAM"],
    )

    ctx.on_cleanup(_cleanup_stack)

    final_status = _poll_until(
        lambda: _stack_status(ctx, stack_name),
        lambda st: st in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED", "ROLLBACK_FAILED"),
        timeout_s=150.0,
        interval_s=10.0,
    )
    assert final_status == "CREATE_COMPLETE", f"stack did not deploy cleanly: {final_status}"

    bucket = _stack_output(ctx, stack_name, "BucketName")
    assert bucket, f"stack {stack_name} has no BucketName output"

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real cfn-deployed pipeline fixture\n")
    s3.put_object(Bucket=bucket, Key="source/source.zip", Body=buf.getvalue())

    action_type_id = {"category": "Build", "owner": "Custom", "provider": provider, "version": "1"}
    execution_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    job = _find_build_job_for_execution(ctx, action_type_id, execution_id, timeout_s=80.0)
    assert job is not None, f"execution {execution_id} never reached the Build action's job queue"
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    cp.put_job_success_result(jobId=job["id"])

    execution = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=execution_id)[
            "pipelineExecution"
        ],
        lambda ex: ex["status"] in ("Succeeded", "Failed", "Stopped", "Superseded", "Cancelled"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert execution["status"] == "Succeeded", f"CFN-deployed pipeline did not run to completion: {execution}"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _stack_status(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    try:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    except Exception:
        return None
    if not stacks:
        return None
    return stacks[0]["StackStatus"]


def _stack_output(ctx, stack_name, key):
    cfn = ctx.client("cloudformation")
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    if not stacks:
        return None
    for out in stacks[0].get("Outputs", []):
        if out["OutputKey"] == key:
            return out["OutputValue"]
    return None


def _empty_bucket(ctx, bucket) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _find_build_job_for_execution(ctx, action_type_id, execution_id, timeout_s=180.0, interval_s=5.0):
    """Poll for a job, but only accept one tied to *this* pipelineExecutionId.

    CodePipeline auto-starts an initial execution as soon as the stack's
    Pipeline resource is created, so the first job PollForJobs hands back may
    belong to that earlier execution rather than the one this check just
    started -- filtering on data.pipelineContext.pipelineExecutionId keeps the
    two from being conflated.
    """
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        jobs = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=10).get("jobs", [])
        for job in jobs:
            if job.get("data", {}).get("pipelineContext", {}).get("pipelineExecutionId") == execution_id:
                return job
        time.sleep(interval_s)
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
