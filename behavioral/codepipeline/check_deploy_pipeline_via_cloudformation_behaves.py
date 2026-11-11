"""deploy-pipeline-via-cloudformation-behaves."""
from __future__ import annotations

import io
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-pipeline-via-cloudformation-behaves"
GROUP = "server-side"
SERVICES = ["codepipeline"]

_TERMINAL = {"Succeeded", "Failed", "Stopped", "Superseded", "Cancelled"}

_TEMPLATE = """
AWSTemplateFormatVersion: "2010-09-09"
Parameters:
  PipelineNameParam:
    Type: String
Resources:
  SourceBucket:
    Type: AWS::S3::Bucket
    Properties:
      VersioningConfiguration:
        Status: Enabled
  ArtifactBucket:
    Type: AWS::S3::Bucket
    Properties:
      VersioningConfiguration:
        Status: Enabled
  DeployBucket:
    Type: AWS::S3::Bucket
    Properties:
      VersioningConfiguration:
        Status: Enabled
  PipelineRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              Service: codepipeline.amazonaws.com
            Action: sts:AssumeRole
      Policies:
        - PolicyName: s3-access
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Effect: Allow
                Action: "s3:*"
                Resource:
                  - !GetAtt SourceBucket.Arn
                  - !Sub "${SourceBucket.Arn}/*"
                  - !GetAtt ArtifactBucket.Arn
                  - !Sub "${ArtifactBucket.Arn}/*"
                  - !GetAtt DeployBucket.Arn
                  - !Sub "${DeployBucket.Arn}/*"
  Pipeline:
    Type: AWS::CodePipeline::Pipeline
    Properties:
      Name: !Ref PipelineNameParam
      RoleArn: !GetAtt PipelineRole.Arn
      ArtifactStore:
        Type: S3
        Location: !Ref ArtifactBucket
      Stages:
        - Name: Source
          Actions:
            - Name: SourceAction
              ActionTypeId:
                Category: Source
                Owner: AWS
                Provider: S3
                Version: "1"
              OutputArtifacts:
                - Name: SourceArtifact
              Configuration:
                S3Bucket: !Ref SourceBucket
                S3ObjectKey: app.zip
                PollForSourceChanges: "false"
        - Name: Deploy
          Actions:
            - Name: DeployAction
              ActionTypeId:
                Category: Deploy
                Owner: AWS
                Provider: S3
                Version: "1"
              InputArtifacts:
                - Name: SourceArtifact
              Configuration:
                BucketName: !Ref DeployBucket
                Extract: "true"
Outputs:
  SourceBucketName:
    Value: !Ref SourceBucket
  DeployBucketName:
    Value: !Ref DeployBucket
  ArtifactBucketName:
    Value: !Ref ArtifactBucket
  PipelineNameOut:
    Value: !Ref Pipeline
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipeline deployed via CloudFormation is not just CREATE_COMPLETE: GetPipeline
    returns its real structure and StartPipelineExecution actually runs the S3
    source -> S3 deploy workflow end to end, landing the object in the deploy bucket."""
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    cfn = ctx.client("cloudformation")

    pipeline_name = ctx.unique_name("sim2real-cp-cfn-")
    stack_name = ctx.unique_name("sim2real-cp-cfn-stack-")

    outputs = _deploy_stack(ctx, cfn, stack_name, pipeline_name)
    source_bucket = outputs["SourceBucketName"]
    deploy_bucket = outputs["DeployBucketName"]

    s3.put_object(Bucket=source_bucket, Key="app.zip", Body=_make_zip_bytes())

    got = cp.get_pipeline(name=pipeline_name)
    assert got["pipeline"]["name"] == pipeline_name, (
        f"expected GetPipeline to echo name {pipeline_name!r}, got {got['pipeline']['name']!r}"
    )
    stage_names = [s["name"] for s in got["pipeline"]["stages"]]
    assert stage_names == ["Source", "Deploy"], (
        f"expected stages ['Source', 'Deploy'], got {stage_names!r}"
    )

    execution = _run_and_await_pipeline(
        cp, pipeline_name, timeout_s=180.0, interval_s=5.0, propagation_deadline_s=90.0
    )
    assert execution["status"] == "Succeeded", (
        f"pipeline execution must reach Succeeded, got {execution['status']!r}: {execution!r}"
    )

    state = cp.get_pipeline_state(name=pipeline_name)
    stage_by_name = {s["stageName"]: s for s in state["stageStates"]}
    deploy_status = stage_by_name["Deploy"]["latestExecution"]["status"]
    assert deploy_status == "Succeeded", (
        f"expected the Deploy stage's latest execution to be Succeeded, got {deploy_status!r}"
    )

    listing = s3.list_objects_v2(Bucket=deploy_bucket)
    keys = {obj["Key"] for obj in listing.get("Contents", [])}
    assert "app.txt" in keys, (
        f"expected app.txt to be unzipped into the deploy bucket, found keys {keys!r}"
    )


def _make_zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.txt", "hello-codepipeline")
    return buf.getvalue()


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _poll_execution(cp, name, exec_id, predicate, timeout_s=180.0, interval_s=5.0):
    """Poll GetPipelineExecution, tolerating the brief propagation window right
    after StartPipelineExecution where the new execution id is not yet visible."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cp.get_pipeline_execution(
                pipelineName=name, pipelineExecutionId=exec_id
            )["pipelineExecution"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "PipelineExecutionNotFoundException":
                time.sleep(interval_s)
                continue
            raise
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _run_and_await_pipeline(cp, name, *, timeout_s, interval_s, propagation_deadline_s):
    """CreatePipeline (run synchronously by the stack's Pipeline resource) validates the
    role's trust policy, so stack CREATE_COMPLETE already proves that much. What it does not
    prove is that the role's inline S3-access policy has propagated -- CodePipeline only
    exercises that policy for real when an execution's Source/Deploy action assumes the role.
    IAM exposes no condition to poll for "the policy is visible now", so the bounded retry on
    the actual run IS the wait: retry a fresh execution only while the failure looks like that
    specific access error, never for any other reason."""
    import time

    deadline = time.monotonic() + propagation_deadline_s
    while True:
        exec_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
        execution = _poll_execution(
            cp, name, exec_id, lambda e: e["status"] in _TERMINAL,
            timeout_s=timeout_s, interval_s=interval_s,
        )
        if execution["status"] == "Succeeded":
            return execution
        if time.monotonic() >= deadline or not _looks_like_role_propagation_failure(cp, name):
            return execution
        time.sleep(interval_s)


def _looks_like_role_propagation_failure(cp, name) -> bool:
    state = cp.get_pipeline_state(name=name)
    for stage in state.get("stageStates", []):
        for action in stage.get("actionStates", []):
            latest = action.get("latestExecution", {})
            if latest.get("status") != "Failed":
                continue
            details = latest.get("errorDetails") or {}
            text = f"{details.get('code', '')} {details.get('message', '')}".lower()
            if "accessdenied" in text or "not authorized" in text or "assumerole" in text:
                return True
    return False


def _empty_bucket(s3, bucket_name: str) -> None:
    try:
        versions = s3.list_object_versions(Bucket=bucket_name)
        to_delete = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in versions.get("Versions", []) + versions.get("DeleteMarkers", [])
        ]
        if to_delete:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": to_delete}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _deploy_stack(ctx, cfn, stack_name: str, pipeline_name: str) -> dict:
    s3 = ctx.client("s3")

    def _cleanup():
        try:
            desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
            outs = {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}
            for key in ("SourceBucketName", "DeployBucketName", "ArtifactBucketName"):
                if key in outs:
                    _empty_bucket(s3, outs[key])
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] in ("NoSuchBucket",) or
                (exc.response["Error"]["Code"] == "ValidationError"
                 and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
        try:
            cfn.delete_stack(StackName=stack_name)
            cfn.get_waiter("stack_delete_complete").wait(
                StackName=stack_name,
                WaiterConfig={"Delay": 2, "MaxAttempts": 450},
            )
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" in exc.response["Error"].get("Message", "")
            ):
                raise

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[{"ParameterKey": "PipelineNameParam", "ParameterValue": pipeline_name}],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )

    ctx.on_cleanup(_cleanup)

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )
    desc = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in desc.get("Outputs", [])}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
