"""e2e-pipeline-create-run-approve-complete-teardown."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-pipeline-create-run-approve-complete-teardown"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """End-to-end: create a pipeline with a manual approval stage, start an execution,
    observe it pause pending approval, approve it, observe the pipeline reach Succeeded,
    then delete the pipeline and confirm it is gone."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    source_action = _create_custom_action_type(ctx, "Source", ctx.unique_name("SimSrc").replace("-", ""), output_range=(1, 1))
    build_action = _create_custom_action_type(ctx, "Build", ctx.unique_name("SimBld").replace("-", ""), input_range=(1, 1))

    name = ctx.unique_name("sim2real-cp-")
    pipeline_def = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
                "name": "Source",
                "actions": [
                    {
                        "name": "Source",
                        "actionTypeId": {"category": "Source", "owner": "Custom", "provider": source_action["provider"], "version": "1"},
                        "outputArtifacts": [{"name": "SourceOutput"}],
                        "configuration": {},
                        "runOrder": 1,
                    }
                ],
            },
            {
                "name": "Approval",
                "actions": [
                    {
                        "name": "ManualApproval",
                        "actionTypeId": {"category": "Approval", "owner": "AWS", "provider": "Manual", "version": "1"},
                        "configuration": {},
                        "runOrder": 1,
                    }
                ],
            },
            {
                "name": "Build",
                "actions": [
                    {
                        "name": "Build",
                        "actionTypeId": {"category": "Build", "owner": "Custom", "provider": build_action["provider"], "version": "1"},
                        "inputArtifacts": [{"name": "SourceOutput"}],
                        "configuration": {},
                        "runOrder": 1,
                    }
                ],
            },
        ],
    }
    _create_pipeline(ctx, pipeline_def, tags=[{"key": "sim2real", "value": CHECK}])

    # CodePipeline automatically kicks off an initial execution the moment the pipeline
    # is created. Drain it fully (source -> approve -> build) before starting the
    # execution we actually want to observe, so its jobs/approval token don't get
    # interleaved with ours.
    _complete_job_success(ctx, source_action)
    initial_token = _poll_until(
        lambda: _find_approval_action(cp, name),
        lambda action: action is not None and action.get("latestExecution", {}).get("token"),
        timeout_s=60.0,
    )["latestExecution"]["token"]
    cp.put_approval_result(
        pipelineName=name,
        stageName="Approval",
        actionName="ManualApproval",
        result={"summary": "draining initial auto-triggered execution", "status": "Approved"},
        token=initial_token,
    )
    _complete_job_success(ctx, build_action)
    _poll_until(
        lambda: cp.list_pipeline_executions(pipelineName=name)["pipelineExecutionSummaries"],
        lambda execs: bool(execs) and all(e["status"] != "InProgress" for e in execs),
        timeout_s=180.0,
    )

    exec_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    _complete_job_success(ctx, source_action)

    token = _poll_until(
        lambda: _find_approval_action(cp, name),
        lambda action: action is not None and action.get("latestExecution", {}).get("token"),
        timeout_s=60.0,
    )["latestExecution"]["token"]

    mid = cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=exec_id)["pipelineExecution"]
    assert mid["status"] == "InProgress", f"expected InProgress while pending approval, got {mid['status']!r}"

    cp.put_approval_result(
        pipelineName=name,
        stageName="Approval",
        actionName="ManualApproval",
        result={"summary": "looks good, approving", "status": "Approved"},
        token=token,
    )

    _complete_job_success(ctx, build_action)

    final = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=exec_id)["pipelineExecution"],
        lambda pe: pe["status"] in ("Succeeded", "Failed"),
        timeout_s=240.0,
    )
    assert final["status"] == "Succeeded", f"expected the approved execution to reach Succeeded, got {final['status']!r}"

    cp.delete_pipeline(name=name)
    refusal = _error_code(lambda: cp.get_pipeline(name=name))
    assert refusal == (
        "PipelineNotFoundException",
        f"Account '{ctx.account}' does not have a pipeline with name '{name}'",
    ), (
        f"expected GetPipeline to report the deleted pipeline gone, got {refusal!r}"
    )

    # The delete is not just a read-miss: a mutation against the dead id must fail the
    # same way, proving the pipeline is gone and not merely absent from one API's view.
    mutate_code = _error_code(lambda: cp.start_pipeline_execution(name=name))
    assert mutate_code == (
        "PipelineNotFoundException",
        f"Pipeline with name {name} does not exist in account {ctx.account}.",
    ), (
        f"expected StartPipelineExecution on the deleted pipeline to fail not-found, got {mutate_code!r}"
    )


def _find_approval_action(cp, pipeline_name: str) -> dict[str, Any] | None:
    state = cp.get_pipeline_state(name=pipeline_name)
    for stage in state["stageStates"]:
        if stage["stageName"] == "Approval":
            action_states = stage.get("actionStates", [])
            if action_states:
                return action_states[0]
    return None


# ===== helpers =====
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
    # Not a region pin: S3's CreateBucket rejects an explicit LocationConstraint for the
    # us-east-1 endpoint itself, so the literal here is an API quirk, not a chosen region.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        resp = s3.list_object_versions(Bucket=name)
        for v in resp.get("Versions", []) + resp.get("DeleteMarkers", []):
            s3.delete_object(Bucket=name, Key=v["Key"], VersionId=v["VersionId"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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


def _safe_delete_pipeline(cp, name: str) -> None:
    try:
        cp.delete_pipeline(name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


def _create_pipeline(ctx, pipeline_def: dict[str, Any], *, tags=None) -> dict[str, Any]:
    cp = ctx.client("codepipeline")
    kwargs: dict[str, Any] = {"pipeline": pipeline_def}
    if tags is not None:
        kwargs["tags"] = tags
    # The role just created (and its inline policy) is eventually consistent: CodePipeline
    # can reject it with InvalidStructureException/ValidationException until the assume-role
    # trust and permissions have propagated. Bound the wait instead of sleeping blind.
    deadline = time.monotonic() + 60.0
    last_err = None
    while True:
        try:
            resp = cp.create_pipeline(**kwargs)
            break
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] not in ("InvalidStructureException", "ValidationException"):
                raise
            if time.monotonic() >= deadline:
                raise AssertionError(f"CreatePipeline still rejecting the role after 60s: {last_err}") from last_err
            time.sleep(5)
    name = pipeline_def["name"]
    ctx.on_cleanup(lambda: _safe_delete_pipeline(cp, name))
    return resp["pipeline"]


def _poll_until(probe, predicate, *, timeout_s=90.0, interval_s=2.0):
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


def _error_code(fn):
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        fn()
    except ClientError as err:
        e = err.response.get("Error", {})
        return e.get("Code"), e.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
