"""deploy-pipeline-cloudformation-executes-on-start."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import WaiterError

from behavioral_harness import tags


CHECK = "deploy-pipeline-cloudformation-executes-on-start"
GROUP = "server-side"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CodePipeline resource deployed via a CloudFormation stack is a fully functional
    pipeline: StartPipelineExecution against it actually runs and reaches a terminal state,
    not merely CREATE_COMPLETE on the stack."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    source_provider = ctx.unique_name("SimSrc").replace("-", "")
    build_provider = ctx.unique_name("SimBld").replace("-", "")
    source_action = _create_custom_action_type(ctx, "Source", source_provider, output_range=(1, 1))
    build_action = _create_custom_action_type(ctx, "Build", build_provider, input_range=(1, 1))

    pipeline_name = ctx.unique_name("sim2real-cp-cfn-")
    outputs = _deploy_cfn(
        ctx,
        _TEMPLATE,
        {
            "PipelineName": pipeline_name,
            "RoleArn": role_arn,
            "BucketName": bucket,
            "SourceProvider": source_provider,
            "BuildProvider": build_provider,
        },
    )
    assert outputs["PipelineName"] == pipeline_name, (
        f"stack output PipelineName={outputs['PipelineName']!r}, expected {pipeline_name!r}"
    )

    got = cp.get_pipeline(name=pipeline_name)
    assert len(got["pipeline"]["stages"]) == 2, (
        f"pipeline {pipeline_name!r} has {len(got['pipeline']['stages'])} stages, expected 2 (Source, Build)"
    )

    # CodePipeline automatically kicks off an initial execution the moment the pipeline
    # is created (whether via API or via a CloudFormation-managed resource). Drain it to
    # a terminal state first so it doesn't contend for the same custom-action jobs as the
    # execution we start explicitly below.
    _complete_job_success(ctx, source_action)
    _complete_job_success(ctx, build_action)
    _poll_until(
        lambda: cp.list_pipeline_executions(pipelineName=pipeline_name)["pipelineExecutionSummaries"],
        lambda execs: bool(execs) and all(e["status"] != "InProgress" for e in execs),
        timeout_s=180.0,
    )

    exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    _complete_job_success(ctx, source_action)
    _complete_job_success(ctx, build_action)

    final = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec_id)["pipelineExecution"],
        lambda pe: pe["status"] in ("Succeeded", "Failed"),
        timeout_s=240.0,
    )
    assert final["status"] == "Succeeded", (
        f"execution {exec_id} on CFN-managed pipeline {pipeline_name!r} reached "
        f"{final['status']!r}, expected 'Succeeded'"
    )


_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "PipelineName": {"Type": "String"},
            "RoleArn": {"Type": "String"},
            "BucketName": {"Type": "String"},
            "SourceProvider": {"Type": "String"},
            "BuildProvider": {"Type": "String"},
        },
        "Resources": {
            "Pipeline": {
                "Type": "AWS::CodePipeline::Pipeline",
                "Properties": {
                    "Name": {"Ref": "PipelineName"},
                    "RoleArn": {"Ref": "RoleArn"},
                    "ArtifactStore": {"Type": "S3", "Location": {"Ref": "BucketName"}},
                    "Stages": [
                        {
                            "Name": "Source",
                            "Actions": [
                                {
                                    "Name": "Source",
                                    "ActionTypeId": {
                                        "Category": "Source",
                                        "Owner": "Custom",
                                        "Provider": {"Ref": "SourceProvider"},
                                        "Version": "1",
                                    },
                                    "OutputArtifacts": [{"Name": "SourceOutput"}],
                                    "Configuration": {},
                                    "RunOrder": 1,
                                }
                            ],
                        },
                        {
                            "Name": "Build",
                            "Actions": [
                                {
                                    "Name": "Build",
                                    "ActionTypeId": {
                                        "Category": "Build",
                                        "Owner": "Custom",
                                        "Provider": {"Ref": "BuildProvider"},
                                        "Version": "1",
                                    },
                                    "InputArtifacts": [{"Name": "SourceOutput"}],
                                    "Configuration": {},
                                    "RunOrder": 1,
                                }
                            ],
                        },
                    ],
                },
            }
        },
        "Outputs": {"PipelineName": {"Value": {"Ref": "Pipeline"}}},
    }
)


_ROLE_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)


def _bucket_policy_doc(bucket_name: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetBucketVersioning", "s3:PutObject"],
                    "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
                }
            ],
        }
    )


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-art-").lower()
    # us-east-1 is the one region S3 rejects as an explicit LocationConstraint; this branches
    # on ctx.region itself, so it still follows wherever the check actually runs.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_object_versions(Bucket=name)
        for v in resp.get("Versions", []) + resp.get("DeleteMarkers", []):
            s3.delete_object(Bucket=name, Key=v["Key"], VersionId=v["VersionId"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_pipeline_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_ROLE_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    policy_name = "artifact-access"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=_bucket_policy_doc(bucket_name))

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_custom_action_type(ctx, category: str, provider: str, *, input_range=(0, 0), output_range=(0, 0)) -> dict[str, str]:
    cp = ctx.client("codepipeline")
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version="1",
        inputArtifactDetails={"minimumCount": input_range[0], "maximumCount": input_range[1]},
        outputArtifactDetails={"minimumCount": output_range[0], "maximumCount": output_range[1]},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version="1"))
    return {"category": category, "owner": "Custom", "provider": provider, "version": "1"}


def _deploy_cfn(ctx, template_body: str, parameters: dict[str, str], *, propagation_timeout_s: float = 90.0) -> dict[str, str]:
    """CloudFormation's AWS::CodePipeline::Pipeline handler calls CreatePipeline under the hood,
    which answers InvalidStructureException while the just-created role is still propagating
    through IAM. That failure surfaces as the whole stack settling in ROLLBACK_COMPLETE, not as
    a raised exception -- so the bounded retry is at stack granularity: delete the rolled-back
    stack and recreate it under the same name until either it succeeds or the deadline passes."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cp-stack-")
    stack_params = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_tags = [{"Key": "sim2real", "Value": CHECK}]

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    ctx.on_cleanup(_cleanup)

    deadline = time.monotonic() + propagation_timeout_s
    while True:
        cfn.create_stack(StackName=stack_name, TemplateBody=template_body, Parameters=stack_params, Tags=stack_tags)
        try:
            cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
            break
        except WaiterError:
            reason = _stack_failure_reason(cfn, stack_name)
            cfn.delete_stack(StackName=stack_name)
            cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})
            transient = "AssumeRole" in reason
            if not transient or time.monotonic() >= deadline:
                raise AssertionError(
                    f"stack {stack_name} did not reach CREATE_COMPLETE: {reason or 'unknown failure'}"
                ) from None
            time.sleep(5)

    resp = cfn.describe_stacks(StackName=stack_name)
    return {o["OutputKey"]: o["OutputValue"] for o in resp["Stacks"][0].get("Outputs", [])}


def _stack_failure_reason(cfn, stack_name: str) -> str:
    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    for event in events:
        if event.get("ResourceStatus", "").endswith("FAILED") and event.get("ResourceStatusReason"):
            return event["ResourceStatusReason"]
    return ""


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_and_ack_job(ctx, action_type_id: dict[str, str], *, timeout_s=90.0) -> str:
    cp = ctx.client("codepipeline")

    def _probe():
        resp = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=5)
        return resp.get("jobs", [])

    jobs = _poll_until(_probe, lambda js: len(js) > 0, timeout_s=timeout_s, interval_s=2.0)
    job = jobs[0]
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    return job["id"]


def _complete_job_success(ctx, action_type_id: dict[str, str], *, output_variables=None, timeout_s=90.0) -> str:
    cp = ctx.client("codepipeline")
    job_id = _poll_and_ack_job(ctx, action_type_id, timeout_s=timeout_s)
    kwargs: dict[str, Any] = {"jobId": job_id}
    if output_variables:
        kwargs["outputVariables"] = output_variables
    cp.put_job_success_result(**kwargs)
    return job_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
