"""stop-completed-execution-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "stop-completed-execution-rejected"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopPipelineExecution on a Succeeded execution fails with PipelineExecutionNotStoppableException and its
    exact message and the status stays Succeeded, while stopping an InProgress execution drives it to Stopped.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)
    action_type_id = _register_custom_action(ctx, category="Build")
    pipeline_name = _create_pipeline(
        ctx,
        role_arn,
        bucket,
        stages=[
            _source_stage(bucket),
            {
                "name": "Build",
                "actions": [
                    {
                        "name": "Build",
                        "actionTypeId": action_type_id,
                        "inputArtifacts": [{"name": "SourceOutput"}],
                        "runOrder": 1,
                    }
                ],
            },
        ],
    )

    # Complete an execution fully so it reaches a terminal state. CreatePipeline
    # auto-starts an execution of its own; settle that away so done_exec_id is the one
    # and only execution that reaches Build.
    done_exec_id = _settle_and_start(cp, pipeline_name, stage_name="Build")

    _drive_job(cp, action_type_id, outcome="success", timeout_s=90.0)
    _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=done_exec_id)[
            "pipelineExecution"
        ]["status"],
        lambda status: status in ("Succeeded", "Failed"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    settled_status = cp.get_pipeline_execution(
        pipelineName=pipeline_name, pipelineExecutionId=done_exec_id
    )["pipelineExecution"]["status"]
    assert settled_status == "Succeeded", (
        f"execution {done_exec_id} must reach Succeeded before the stop-rejection is tested, got {settled_status!r}"
    )

    code, message = _error(
        lambda: cp.stop_pipeline_execution(
            pipelineName=pipeline_name, pipelineExecutionId=done_exec_id, abandon=True, reason="rejected"
        )
    )
    assert code == "PipelineExecutionNotStoppableException", code
    assert message == (
        f"The pipeline execution with ID '{done_exec_id}' in '{pipeline_name}' can't be stopped now. "
        "Either it does not exist in the pipeline, or the pipeline execution has no action "
        "executions in progress."
    ), message

    # The effect must be absent: the completed execution's status is unchanged.
    unchanged = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=done_exec_id)[
        "pipelineExecution"
    ]
    assert unchanged["status"] == "Succeeded", (
        f"a rejected stop must not change the terminal status of {done_exec_id}, got {unchanged['status']!r}"
    )

    # Positive control: a genuinely InProgress execution CAN be stopped.
    running_exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]
    _poll_until(
        lambda: cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1).get("jobs", []),
        lambda jobs: bool(jobs),
        timeout_s=90.0,
        interval_s=3.0,
    )
    cp.stop_pipeline_execution(
        pipelineName=pipeline_name, pipelineExecutionId=running_exec_id, abandon=True, reason="control"
    )
    stopped = _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=running_exec_id)[
            "pipelineExecution"
        ]["status"],
        lambda status: status in ("Stopped", "Succeeded", "Failed"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert stopped == "Stopped", stopped


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _settle_and_start(cp, pipeline_name: str, stage_name: str) -> str:
    """CreatePipeline auto-starts an initial execution. Disable inbound transition into
    the given stage, start our own execution, then re-enable -- the auto-triggered
    execution (if still queued to enter that stage) is superseded by ours, so exactly
    one execution (ours) ever reaches the stage."""
    cp.disable_stage_transition(
        pipelineName=pipeline_name,
        stageName=stage_name,
        transitionType="Inbound",
        reason="sim2real settling the CreatePipeline auto-triggered execution",
    )
    try:
        exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]

        other_id = _poll_until(
            lambda: next(
                (
                    e["pipelineExecutionId"]
                    for e in cp.list_pipeline_executions(pipelineName=pipeline_name).get(
                        "pipelineExecutionSummaries", []
                    )
                    if e["pipelineExecutionId"] != exec_id
                ),
                None,
            ),
            lambda found: found is not None,
            timeout_s=30.0,
            interval_s=2.0,
        )

        def _source_stage_done(execution_id: str) -> bool:
            from botocore.exceptions import ClientError

            try:
                details = cp.list_action_executions(
                    pipelineName=pipeline_name, filter={"pipelineExecutionId": execution_id}
                ).get("actionExecutionDetails", [])
            except ClientError as e:
                # Freshly started executions are briefly unknown to ListActionExecutions
                # even though StartPipelineExecution / ListPipelineExecutions already see
                # them -- an eventual-consistency lag, not evidence the execution is done.
                if e.response["Error"]["Code"] == "PipelineExecutionNotFoundException":
                    return False
                raise
            return any(d["stageName"] == "Source" and d["status"] == "Succeeded" for d in details)

        # The transition may only be re-enabled once BOTH executions have actually
        # finished the Source stage and are genuinely queued at the disabled boundary --
        # otherwise whichever reaches it first (not necessarily ours) is admitted.
        _poll_until(
            lambda: (_source_stage_done(exec_id), _source_stage_done(other_id)),
            lambda pair: all(pair),
            timeout_s=60.0,
            interval_s=3.0,
        )
    finally:
        cp.enable_stage_transition(pipelineName=pipeline_name, stageName=stage_name, transitionType="Inbound")
    return exec_id


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real behavioral check source artifact")
    return buf.getvalue()


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    kwargs = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})

    def _cleanup():
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_object(Bucket=bucket, Key="source.zip", Body=_zip_bytes())
    return bucket


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "artifact-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject",
                    "s3:GetObjectVersion",
                    "s3:PutObject",
                    "s3:GetBucketVersioning",
                    "s3:GetBucketAcl",
                    "s3:GetBucketLocation",
                    "s3:ListBucket",
                ],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _register_custom_action(ctx, category="Build") -> dict:
    cp = ctx.client("codepipeline")
    provider = ctx.unique_name("s2rW")[:35]
    version = "1"
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version))
    return {"category": category, "owner": "Custom", "provider": provider, "version": version}


def _source_stage(bucket: str) -> dict:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "Source",
                "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                "configuration": {
                    "S3Bucket": bucket,
                    "S3ObjectKey": "source.zip",
                    "PollForSourceChanges": "false",
                },
                "outputArtifacts": [{"name": "SourceOutput"}],
            }
        ],
    }


def _create_pipeline(ctx, role_arn: str, bucket: str, stages: list, pipeline_type=None) -> str:
    cp = ctx.client("codepipeline")
    name = ctx.unique_name("sim2real-cp-pl-")
    pipeline = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    if pipeline_type:
        pipeline["pipelineType"] = pipeline_type

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": CHECK}])
            break
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = err.get("Code") == "InvalidStructureException" and "AssumeRole" in err.get("Message", "")
            if not transient or time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


def _drive_job(cp, action_type_id: dict, outcome: str, timeout_s: float = 120.0, action_name: str | None = None):
    def probe():
        return cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=5).get("jobs", [])

    def find(jobs):
        if not jobs:
            return None
        if action_name is None:
            return jobs[0]
        for j in jobs:
            if j["data"]["pipelineContext"]["action"]["name"] == action_name:
                return j
        return None

    jobs = _poll_until(probe, lambda js: find(js) is not None, timeout_s=timeout_s, interval_s=3.0)
    job = find(jobs)
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    if outcome == "success":
        cp.put_job_success_result(jobId=job["id"])
    else:
        cp.put_job_failure_result(
            jobId=job["id"], failureDetails={"type": "JobFailed", "message": "sim2real forced failure"}
        )
    return job


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
