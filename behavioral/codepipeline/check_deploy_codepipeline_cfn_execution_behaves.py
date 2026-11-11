"""deploy-codepipeline-cfn-execution-behaves."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "deploy-codepipeline-cfn-execution-behaves"
GROUP = "deploy"
SERVICES = ["codepipeline"]

_TEMPLATE = {
    "AWSTemplateFormatVersion": "2010-09-09",
    "Parameters": {
        "ArtifactBucketName": {"Type": "String"},
        "SourceObjectKey": {"Type": "String"},
        "PipelineName": {"Type": "String"},
    },
    "Resources": {
        "PipelineRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "codepipeline.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "Policies": [
                    {
                        "PolicyName": "artifact-access",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "s3:GetObject",
                                        "s3:GetObjectVersion",
                                        "s3:PutObject",
                                        "s3:GetBucketVersioning",
                                        "s3:ListBucket",
                                    ],
                                    "Resource": [
                                        {"Fn::Sub": "arn:aws:s3:::${ArtifactBucketName}"},
                                        {"Fn::Sub": "arn:aws:s3:::${ArtifactBucketName}/*"},
                                    ],
                                }
                            ],
                        },
                    }
                ],
            },
        },
        "Pipeline": {
            "Type": "AWS::CodePipeline::Pipeline",
            "Properties": {
                "Name": {"Ref": "PipelineName"},
                "RoleArn": {"Fn::GetAtt": ["PipelineRole", "Arn"]},
                "ArtifactStore": {"Type": "S3", "Location": {"Ref": "ArtifactBucketName"}},
                "Stages": [
                    {
                        "Name": "Source",
                        "Actions": [
                            {
                                "Name": "SourceAction",
                                "ActionTypeId": {
                                    "Category": "Source",
                                    "Owner": "AWS",
                                    "Provider": "S3",
                                    "Version": "1",
                                },
                                "OutputArtifacts": [{"Name": "SourceOutput"}],
                                "Configuration": {
                                    "S3Bucket": {"Ref": "ArtifactBucketName"},
                                    "S3ObjectKey": {"Ref": "SourceObjectKey"},
                                    "PollForSourceChanges": "false",
                                },
                                "RunOrder": 1,
                            }
                        ],
                    },
                    {
                        "Name": "Approve",
                        "Actions": [
                            {
                                "Name": "ManualApproval",
                                "ActionTypeId": {
                                    "Category": "Approval",
                                    "Owner": "AWS",
                                    "Provider": "Manual",
                                    "Version": "1",
                                },
                                "RunOrder": 1,
                            }
                        ],
                    },
                ],
            },
        },
    },
    "Outputs": {"PipelineName": {"Value": {"Ref": "Pipeline"}}},
}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::CodePipeline::Pipeline accepts StartPipelineExecution and
    reports GetPipelineState/GetPipelineExecution transitions through to Succeeded."""
    bucket = _create_artifact_bucket(ctx)
    key = _upload_source_zip(ctx, bucket)
    pipeline_name = ctx.unique_name("sim2real-cp-cfn-")

    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cp-cfn-stack-")

    def _cleanup_stack() -> None:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(_TEMPLATE),
        Parameters=[
            {"ParameterKey": "ArtifactBucketName", "ParameterValue": bucket},
            {"ParameterKey": "SourceObjectKey", "ParameterValue": key},
            {"ParameterKey": "PipelineName", "ParameterValue": pipeline_name},
        ],
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(_cleanup_stack)
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )

    cp = ctx.client("codepipeline")
    declared = cp.get_pipeline(name=pipeline_name)["pipeline"]
    declared_stages = [s["name"] for s in declared["stages"]]
    assert declared_stages == ["Source", "Approve"], (
        f"expected stages ['Source', 'Approve'], got {declared_stages!r}"
    )

    # CodePipeline auto-starts an execution the moment the CFN-managed Pipeline
    # resource exists. Drain that execution to a terminal state first so it can't
    # race the explicit execution below for the same Approve gate.
    _drain_initial_execution(cp, pipeline_name)

    cp.start_pipeline_execution(name=pipeline_name)

    def _probe() -> dict:
        return cp.get_pipeline_state(name=pipeline_name)

    gated = _poll_until(
        _probe,
        lambda s: _action_state(s, "Approve", "ManualApproval").get("latestExecution", {}).get(
            "status"
        )
        == "InProgress",
        timeout_s=120.0,
    )
    token = _action_state(gated, "Approve", "ManualApproval")["latestExecution"]["token"]
    cp.put_approval_result(
        pipelineName=pipeline_name,
        stageName="Approve",
        actionName="ManualApproval",
        result={"status": "Approved", "summary": "behavioral-fidelity cfn deploy"},
        token=token,
    )

    executions = cp.list_pipeline_executions(pipelineName=pipeline_name)[
        "pipelineExecutionSummaries"
    ]
    exec_id = executions[0]["pipelineExecutionId"]

    def _probe_execution() -> dict:
        return cp.get_pipeline_execution(
            pipelineName=pipeline_name, pipelineExecutionId=exec_id
        )["pipelineExecution"]

    # The approval action's own state settles quickly; the aggregate
    # PipelineExecution.status can lag behind it by a bit longer, so confirm the
    # action-level terminal state first before waiting on the execution-level status.
    settled_state = _poll_until(
        _probe,
        lambda s: _action_state(s, "Approve", "ManualApproval")
        .get("latestExecution", {})
        .get("status")
        in ("Succeeded", "Failed"),
        timeout_s=120.0,
    )
    approve_action_status = _action_state(settled_state, "Approve", "ManualApproval")[
        "latestExecution"
    ]["status"]
    assert approve_action_status == "Succeeded", approve_action_status

    final_exec = _poll_until(
        _probe_execution, lambda e: e["status"] in ("Succeeded", "Failed"), timeout_s=120.0
    )
    assert final_exec["status"] == "Succeeded", (
        f"expected execution status Succeeded, got {final_exec['status']!r}"
    )




def _drain_initial_execution(cp, pipeline_name: str) -> None:
    def _probe() -> dict:
        return cp.get_pipeline_state(name=pipeline_name)

    gated = _poll_until(
        _probe,
        lambda s: _action_state(s, "Approve", "ManualApproval").get("latestExecution", {}).get(
            "status"
        )
        == "InProgress",
        timeout_s=120.0,
    )
    token = _action_state(gated, "Approve", "ManualApproval")["latestExecution"]["token"]
    cp.put_approval_result(
        pipelineName=pipeline_name,
        stageName="Approve",
        actionName="ManualApproval",
        result={"status": "Approved", "summary": "draining CFN auto-triggered initial execution"},
        token=token,
    )
    _poll_until(
        lambda: cp.list_pipeline_executions(pipelineName=pipeline_name)["pipelineExecutionSummaries"],
        lambda execs: bool(execs) and all(e["status"] != "InProgress" for e in execs),
        timeout_s=120.0,
    )


def _action_state(state_resp: dict, stage_name: str, action_name: str) -> dict:
    for stage in state_resp["stageStates"]:
        if stage["stageName"] == stage_name:
            for action in stage["actionStates"]:
                if action["actionName"] == action_name:
                    return action
    raise AssertionError(f"action {action_name} not found in stage {stage_name}")


def _poll_until(probe, predicate, *, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value: {last!r}")


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )

    def _cleanup() -> None:
        resp = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
        objs += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _upload_source_zip(ctx, bucket: str, key: str = "source.zip") -> str:
    s3 = ctx.client("s3")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real-behavioral-source")
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    return key


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
