"""stop-pipeline-execution-not-stoppable-rejected."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-pipeline-execution-not-stoppable-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopPipelineExecution against an execution that already reached a
    terminal state is rejected with PipelineExecutionNotStoppableException, and
    the execution's terminal status is left unchanged."""
    cp = ctx.client("codepipeline")
    src_type = _create_custom_action_type(ctx, "Source", 0, 0, 1, 1)
    build_type = _create_custom_action_type(ctx, "Build", 1, 1, 0, 1)
    stages = [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "SourceAction",
                    "actionTypeId": src_type,
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }
            ],
        },
        {
            "name": "Build",
            "actions": [
                {
                    "name": "BuildAction",
                    "actionTypeId": build_type,
                    "inputArtifacts": [{"name": "SourceOutput"}],
                    "outputArtifacts": [{"name": "BuildOutput"}],
                }
            ],
        },
    ]
    pipeline_name = _create_pipeline(ctx, stages)
    _settle_auto_triggered_execution(ctx, pipeline_name, src_type)

    # --- drive execution #1 to a terminal (Failed) state first ---
    exec1 = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    job1 = _poll_for_job(ctx, src_type, exec1)
    cp.acknowledge_job(jobId=job1["id"], nonce=job1["nonce"])
    cp.put_job_failure_result(
        jobId=job1["id"], failureDetails={"type": "JobFailed", "message": "fail-fast"}
    )
    _poll_until(
        lambda: cp.get_pipeline_execution(
            pipelineName=pipeline_name, pipelineExecutionId=exec1
        )["pipelineExecution"]["status"],
        lambda status: status == "Failed",
        timeout_s=120,
        interval_s=4,
    )

    code, message = _error(
        lambda: cp.stop_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec1)
    )
    assert code == "PipelineExecutionNotStoppableException", code
    assert message == (
        f"The pipeline execution with ID '{exec1}' in '{pipeline_name}' can't be stopped now. "
        "Either it does not exist in the pipeline, or the pipeline execution has no action "
        "executions in progress."
    ), message

    # effect absent: execution #1's terminal status must remain Failed, not Stopping/Stopped
    still_failed = cp.get_pipeline_execution(
        pipelineName=pipeline_name, pipelineExecutionId=exec1
    )["pipelineExecution"]
    assert still_failed["status"] == "Failed", still_failed

    # --- positive control: an execution still InProgress CAN be stopped ---
    exec2 = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    _poll_for_job(ctx, src_type, exec2)  # ensure the job exists; deliberately left un-acknowledged

    cp.stop_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec2)
    stopped = _poll_until(
        lambda: cp.get_pipeline_execution(
            pipelineName=pipeline_name, pipelineExecutionId=exec2
        )["pipelineExecution"],
        lambda e: e["status"] in ("Stopping", "Stopped", "Cancelled"),
        timeout_s=120,
        interval_s=4,
    )
    assert stopped["status"] in ("Stopping", "Stopped", "Cancelled"), stopped


def _short_id() -> str:
    return uuid.uuid4().hex[:10]


def _error(fn):
    """(code, message) of the ClientError ``fn`` raises; an unexpected success fails loudly."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _settle_auto_triggered_execution(ctx, pipeline_name: str, src_type: dict) -> None:
    """CreatePipeline may auto-start an execution of its own before we ever call
    StartPipelineExecution. Left alone, its Source job and ours would both sit in the
    same PollForJobs queue for src_type, so the job we grab for our own execution is
    not guaranteed to be the one we asked for. If one shows up within a short bounded
    wait, resolve it (successfully; its outcome is irrelevant to this check) so only
    our own executions ever contend for src_type's queue afterward; if none shows up,
    there is nothing to settle."""
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + 20.0
    auto_exec_id = None
    while time.monotonic() < deadline:
        executions = cp.list_pipeline_executions(pipelineName=pipeline_name)["pipelineExecutionSummaries"]
        if executions:
            auto_exec_id = executions[0]["pipelineExecutionId"]
            break
        time.sleep(2)
    if auto_exec_id is None:
        return
    job = _poll_for_job(ctx, src_type, auto_exec_id, timeout_s=20, required=False)
    if job is None:
        return
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    cp.put_job_success_result(jobId=job["id"])


def _poll_for_job(
    ctx, action_type_id: dict, execution_id: str, timeout_s: float = 90.0, required: bool = True
) -> dict | None:
    """Poll for the job belonging to `execution_id` specifically -- PollForJobs is not
    guaranteed to hand back jobs in the order their executions were started, so the
    first job in the batch is not necessarily ours. When `required`, times out into an
    AssertionError naming the execution ids that WERE seen instead of just "nothing
    matched"; otherwise returns None so a caller that is merely draining a queue it
    does not know is occupied can treat "nothing showed up" as a normal outcome."""
    cp = ctx.client("codepipeline")
    seen: set[str] = set()
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for job in cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=10).get("jobs", []):
            job_exec_id = job["data"]["pipelineContext"]["pipelineExecutionId"]
            seen.add(job_exec_id)
            if job_exec_id == execution_id:
                return job
        time.sleep(3)
    if required:
        raise AssertionError(
            f"no job for execution {execution_id} within {timeout_s}s; "
            f"execution ids seen in the queue instead: {sorted(seen)}"
        )
    return None


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-art-").lower()
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        try:
            versions = s3.list_object_versions(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
            return
        objs = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in versions.get("Versions", []) + versions.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_pipeline_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "codepipeline.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_name = "artifact-access"
    policy = json.dumps(
        {
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
                        f"arn:aws:s3:::{bucket_name}",
                        f"arn:aws:s3:::{bucket_name}/*",
                    ],
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=policy)

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_custom_action_type(ctx, category: str, min_in: int, max_in: int, min_out: int, max_out: int):
    cp = ctx.client("codepipeline")
    provider = f"S2R{category[:2]}{_short_id()}"[:35]
    version = "1"
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": min_in, "maximumCount": max_in},
        outputArtifactDetails={"minimumCount": min_out, "maximumCount": max_out},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version)
    )
    return {"category": category, "owner": "Custom", "provider": provider, "version": version}


def _create_pipeline(ctx, stages: list[dict], pipeline_type: str = "V1") -> str:
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    name = ctx.unique_name("sim2real-cp-")
    pipeline_def: dict[str, Any] = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    pipeline_tags = [{"key": "sim2real", "value": CHECK}]
    if pipeline_type == "V2":
        pipeline_def["pipelineType"] = "V2"

    # Bounded retry: the role was just created, and CodePipeline may reject the
    # definition until IAM has propagated it far enough for CodePipeline to assume it.
    last_err: Exception | None = None
    for _ in range(6):
        try:
            cp.create_pipeline(pipeline=pipeline_def, tags=pipeline_tags)
            break
        except ClientError as e:
            last_err = e
            time.sleep(5)
    else:
        raise last_err  # type: ignore[misc]

    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
