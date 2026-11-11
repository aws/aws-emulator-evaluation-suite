"""job-success-output-variables-round-trip."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-success-output-variables-round-trip"
GROUP = "state-machine"
SERVICES = ["codepipeline"]


# ListActionExecutions output.outputVariables is the documented read-back of an action's
# output variables; GetPipelineExecution and GetJobDetails do not carry them.
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Output variable values (including base64-like padding and punctuation) set via
    PutJobSuccessResult are preserved exactly and retrievable via ListActionExecutions."""
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
                "name": "Build",
                "actions": [
                    {
                        "name": "Build",
                        "actionTypeId": {"category": "Build", "owner": "Custom", "provider": build_action["provider"], "version": "1"},
                        "inputArtifacts": [{"name": "SourceOutput"}],
                        "configuration": {},
                        "namespace": "BuildNS",
                        "runOrder": 1,
                    }
                ],
            },
        ],
    }
    _create_pipeline(ctx, pipeline_def, tags=[{"key": "sim2real", "value": CHECK}])

    # CodePipeline automatically kicks off an initial execution the moment the pipeline
    # is created; drain it before starting our own so its jobs don't get interleaved
    # with the one under test.
    _complete_job_success(ctx, source_action)
    _complete_job_success(ctx, build_action)
    _poll_until(
        lambda: cp.list_pipeline_executions(pipelineName=name)["pipelineExecutionSummaries"],
        lambda execs: bool(execs) and all(e["status"] != "InProgress" for e in execs),
        timeout_s=180.0,
    )

    exec_id = cp.start_pipeline_execution(name=name)["pipelineExecutionId"]
    _complete_job_success(ctx, source_action)

    build_job_id = _poll_and_ack_job(ctx, build_action)
    got_before = cp.get_job_details(jobId=build_job_id)
    actual_exec_id = got_before["jobDetails"]["data"]["pipelineContext"]["pipelineExecutionId"]
    assert actual_exec_id == exec_id, f"job pipelineExecutionId={actual_exec_id!r} != started exec_id={exec_id!r}"

    special_value = "QUJDREVGRw==+/-_test!!"
    cp.put_job_success_result(jobId=build_job_id, outputVariables={"BuildVar": special_value})

    _poll_until(
        lambda: cp.get_pipeline_execution(pipelineName=name, pipelineExecutionId=exec_id)["pipelineExecution"],
        lambda pe: pe["status"] in ("Succeeded", "Failed"),
        timeout_s=240.0,
    )

    def _probe_build_details():
        listed = cp.list_action_executions(
            pipelineName=name, filter={"pipelineExecutionId": exec_id}
        )
        return next(
            (d for d in listed["actionExecutionDetails"] if d["actionName"] == "Build"), None
        )

    # ListActionExecutions is a historical-record API with its own eventual-consistency
    # lag behind the pipeline-execution status just polled above, so the outputVariables
    # may not be attached yet on the first read.
    build_details = _poll_until(
        _probe_build_details,
        lambda d: d is not None and bool(d.get("output", {}).get("outputVariables")),
        timeout_s=240.0,
        interval_s=5.0,
    )
    actual = build_details["output"]["outputVariables"]
    expected = {"BuildVar": special_value}
    assert actual == expected, f"outputVariables={actual!r} != expected={expected!r}"


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
    # S3 rejects a LocationConstraint of us-east-1 specifically; this is a comparison
    # against ctx.region, not a hardcoded target region (checks run in us-west-2).
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
    last_err = None
    resp = None
    for _ in range(6):
        try:
            resp = cp.create_pipeline(**kwargs)
            break
        except ClientError as err:
            last_err = err
            # The role and its inline policy were just created; IAM propagation lags
            # CreatePipeline's own role-assumability validation, which surfaces here as
            # InvalidStructureException/ValidationException. Bounded retry, not a sleep.
            if err.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise last_err
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
