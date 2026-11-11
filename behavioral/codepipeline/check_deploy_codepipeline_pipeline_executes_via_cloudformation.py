"""deploy-codepipeline-pipeline-executes-via-cloudformation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-codepipeline-pipeline-executes-via-cloudformation"
GROUP = "server-side"
SERVICES = ["codepipeline"]

_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ArtifactBucket": {"Type": "AWS::S3::Bucket"},
            "SourceBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {"VersioningConfiguration": {"Status": "Enabled"}},
            },
            "DeployBucket": {"Type": "AWS::S3::Bucket"},
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
                            "PolicyName": "pipeline-access",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "s3:GetObject",
                                            "s3:GetObjectVersion",
                                            "s3:GetBucketVersioning",
                                            "s3:PutObject",
                                            "s3:PutObjectAcl",
                                            "s3:GetBucketLocation",
                                            "s3:ListBucket",
                                        ],
                                        "Resource": [
                                            {"Fn::GetAtt": ["SourceBucket", "Arn"]},
                                            {"Fn::Sub": "${SourceBucket.Arn}/*"},
                                            {"Fn::GetAtt": ["DeployBucket", "Arn"]},
                                            {"Fn::Sub": "${DeployBucket.Arn}/*"},
                                            {"Fn::GetAtt": ["ArtifactBucket", "Arn"]},
                                            {"Fn::Sub": "${ArtifactBucket.Arn}/*"},
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
                    "RoleArn": {"Fn::GetAtt": ["PipelineRole", "Arn"]},
                    "ArtifactStore": {"Type": "S3", "Location": {"Ref": "ArtifactBucket"}},
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
                                    "OutputArtifacts": [{"Name": "SourceArtifact"}],
                                    "Configuration": {
                                        "S3Bucket": {"Ref": "SourceBucket"},
                                        "S3ObjectKey": "source.txt",
                                        "PollForSourceChanges": "false",
                                    },
                                }
                            ],
                        },
                        {
                            "Name": "Deploy",
                            "Actions": [
                                {
                                    "Name": "DeployAction",
                                    "ActionTypeId": {
                                        "Category": "Deploy",
                                        "Owner": "AWS",
                                        "Provider": "S3",
                                        "Version": "1",
                                    },
                                    "InputArtifacts": [{"Name": "SourceArtifact"}],
                                    "Configuration": {
                                        "BucketName": {"Ref": "DeployBucket"},
                                        "Extract": "false",
                                        "ObjectKey": "deployed.txt",
                                    },
                                }
                            ],
                        },
                    ],
                },
            },
        },
        "Outputs": {
            "PipelineName": {"Value": {"Ref": "Pipeline"}},
            "SourceBucketName": {"Value": {"Ref": "SourceBucket"}},
            "DeployBucketName": {"Value": {"Ref": "DeployBucket"}},
            "ArtifactBucketName": {"Value": {"Ref": "ArtifactBucket"}},
        },
    }
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CodePipeline pipeline from a CREATE_COMPLETE CloudFormation stack runs on
    StartPipelineExecution to Succeeded, and the deploy bucket then holds the source object byte for byte."""
    outputs = _deploy_cfn(ctx, _TEMPLATE)
    s3 = ctx.client("s3")
    content = b"cfn-pipeline-source-payload"
    s3.put_object(Bucket=outputs["SourceBucketName"], Key="source.txt", Body=content)

    cp = ctx.client("codepipeline")
    pipeline_name = outputs["PipelineName"]
    exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]

    def _probe_execution():
        # GetPipelineExecution has a brief propagation window right after
        # StartPipelineExecution where the new execution id is not yet visible and
        # the call 404s; treat that as "not yet terminal" rather than a hard error.
        try:
            return cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec_id)[
                "pipelineExecution"
            ]
        except ClientError as e:
            if e.response["Error"]["Code"] == "PipelineExecutionNotFoundException":
                return None
            raise

    terminal = _poll_until(
        ctx,
        _probe_execution,
        lambda e: e is not None and e["status"] in ("Succeeded", "Failed", "Stopped", "Cancelled", "Superseded"),
        timeout_s=300,
        interval_s=2,
    )
    assert terminal is not None, "pipeline execution never reached a terminal state"
    assert terminal["status"] == "Succeeded", f"unexpected terminal status: {terminal['status']}"

    deployed = s3.get_object(Bucket=outputs["DeployBucketName"], Key="deployed.txt")
    got = deployed["Body"].read()
    assert got == content, f"deployed object bytes {got!r} != source bytes {content!r}"


def _poll_until(ctx, probe, predicate, timeout_s=30.0, interval_s=2.0):
    """probe() until predicate holds; None at timeout_s, capped by the runner's remaining time
    less 5 s. Raises TimeoutError (not graded) when that remaining time, not timeout_s, ends it."""
    left = ctx.time_left()
    capped = left is not None and left - 5.0 < timeout_s
    deadline = time.monotonic() + (max(1.0, left - 5.0) if capped else timeout_s)
    while True:
        result = probe()
        if predicate(result):
            return result
        if time.monotonic() >= deadline:
            if capped:
                raise TimeoutError("the run budget ended before the poll's own deadline; not graded")
            return None
        time.sleep(interval_s)


def _stack_outputs(cfn, stack_name: str) -> dict[str, str]:
    stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
    return {o["OutputKey"]: o["OutputValue"] for o in stacks[0].get("Outputs", [])}


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _deploy_cfn(ctx, template_body: str) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cp-stack-")

    def _cleanup() -> None:
        try:
            outs = _stack_outputs(cfn, stack_name)
            for key in ("SourceBucketName", "DeployBucketName", "ArtifactBucketName"):
                bucket = outs.get(key)
                if bucket:
                    try:
                        _empty_bucket(ctx, bucket)
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "NoSuchBucket":
                            raise
        except ClientError as exc:
            if not (
                exc.response["Error"]["Code"] in ("NoSuchBucket",) or
                (exc.response["Error"]["Code"] == "ValidationError"
                 and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_cleanup)
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    return _stack_outputs(cfn, stack_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
