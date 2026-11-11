"""pipeline-execution-timestamp-precision-preserved."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "pipeline-execution-timestamp-precision-preserved"
GROUP = "server-side"
SERVICES = ["codepipeline"]

# NOTE on scope: the PipelineExecution object returned by GetPipelineExecution has no
# startTime/lastUpdateTime fields at all (see API_PipelineExecution.html) -- those live on
# PipelineExecutionSummary, returned by ListPipelineExecutions. This check still exercises
# GetPipelineExecution (as required) to confirm the execution's identity/status is stable across
# repeated reads, and sources the actual sub-second timestamp round-trip assertion from
# ListPipelineExecutions, which is where AWS documents those fields living.


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListPipelineExecutions' startTime/lastUpdateTime retain full sub-second precision, unchanged across repeated reads; GetPipelineExecution stays consistent throughout."""
    cp = ctx.client("codepipeline")
    bucket = _create_artifact_bucket(ctx)
    role_arn = _create_pipeline_role(ctx, bucket)

    source_provider = ctx.unique_name("sim2real-cp-src-")
    build_provider = ctx.unique_name("sim2real-cp-bld-")
    _create_custom_action_type(ctx, "Source", source_provider, "1", 0, 0, 1, 1)
    _create_custom_action_type(ctx, "Build", build_provider, "1", 1, 1, 0, 1)

    pipeline_name = ctx.unique_name("sim2real-cp-pipe-")
    pipeline = {
        "name": pipeline_name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": [
            {
                "name": "Source",
                "actions": [{
                    "name": "SourceAction",
                    "actionTypeId": {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"},
                    "outputArtifacts": [{"name": "SourceOutput"}],
                    "configuration": {},
                }],
            },
            {
                "name": "Build",
                "actions": [{
                    "name": "BuildAction",
                    "actionTypeId": {"category": "Build", "owner": "Custom", "provider": build_provider, "version": "1"},
                    "inputArtifacts": [{"name": "SourceOutput"}],
                    "configuration": {},
                }],
            },
        ],
    }
    _wait_role_usable(lambda: cp.create_pipeline(pipeline=pipeline))
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))

    exec_id = cp.start_pipeline_execution(name=pipeline_name)["pipelineExecutionId"]

    # GetPipelineExecution: confirm the execution is visible and its identity/status are stable
    # across repeated reads (the piece of "the same execution, read twice" that this API can
    # actually attest to).
    read1 = _poll_until_execution_visible(ctx, pipeline_name, exec_id)
    summary1 = _poll_until_summary_visible(ctx, pipeline_name, exec_id)

    _poll_one_job(
        ctx, {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"}
    )

    read2 = cp.get_pipeline_execution(pipelineName=pipeline_name, pipelineExecutionId=exec_id)["pipelineExecution"]
    assert read2["pipelineExecutionId"] == read1["pipelineExecutionId"] == exec_id
    assert read2["pipelineName"] == read1["pipelineName"] == pipeline_name

    summary2 = _get_summary(ctx, pipeline_name, exec_id)
    assert summary2 is not None, f"pipelineExecutionId={exec_id} disappeared from ListPipelineExecutions"

    start1, start2 = summary1["startTime"], summary2["startTime"]
    assert start1 == start2, f"startTime drifted between ListPipelineExecutions reads: {start1!r} vs {start2!r}"
    # boto3 surfaces AWS timestamps as datetime objects; assert the underlying value actually
    # carries sub-second resolution rather than having been rounded down to whole seconds by
    # the emulator (a real StartPipelineExecution timestamp is almost never exactly on the
    # second boundary).
    assert start1.microsecond != 0 or start2.microsecond != 0, (
        "startTime has zero microseconds on both reads -- sub-second precision looks truncated"
    )
    last_update2 = summary2.get("lastUpdateTime")
    assert last_update2 is not None, "lastUpdateTime missing from ListPipelineExecutions summary"
    assert last_update2.microsecond != 0, (
        "lastUpdateTime has zero microseconds -- sub-second precision looks truncated"
    )


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_object_versions(Bucket=bucket)
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in resp.get("DeleteMarkers", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_pipeline_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    })
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject", "s3:GetBucketVersioning", "s3:GetBucketAcl", "s3:GetBucketLocation", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    })
    iam.put_role_policy(RoleName=role_name, PolicyName="artifact-access", PolicyDocument=policy_doc)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="artifact-access"))
    return role["Arn"]


def _wait_role_usable(fn, *, timeout_s: float = 90.0, interval_s: float = 3.0) -> Any:
    """IAM role/trust propagation is not directly observable, so poll the operation that
    actually needs it (create_pipeline) instead of sleeping blindly."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in (
                "InvalidStructureException",
                "InvalidParameterValueException",
                "InvalidRoleException",
            ) or time.monotonic() > deadline:
                raise
            time.sleep(interval_s)


def _create_custom_action_type(ctx, category, provider, version, in_min, in_max, out_min, out_max, config_props=None):
    cp = ctx.client("codepipeline")
    kwargs = {
        "category": category,
        "provider": provider,
        "version": version,
        "inputArtifactDetails": {"minimumCount": in_min, "maximumCount": in_max},
        "outputArtifactDetails": {"minimumCount": out_min, "maximumCount": out_max},
    }
    if config_props:
        kwargs["configurationProperties"] = config_props
    cp.create_custom_action_type(**kwargs)
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version))


def _poll_one_job(ctx, action_type_id, timeout_s=60.0, interval_s=2.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1)
        jobs = resp.get("jobs", [])
        if jobs:
            return jobs[0]
        time.sleep(interval_s)
    raise AssertionError(f"no job appeared for actionTypeId={action_type_id} within {timeout_s}s")


def _poll_until_execution_visible(ctx, pipeline_name, exec_id, timeout_s=30.0, interval_s=1.5):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cp.get_pipeline_execution(
                pipelineName=pipeline_name, pipelineExecutionId=exec_id
            )["pipelineExecution"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "PipelineExecutionNotFoundException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"pipelineExecutionId={exec_id} never became visible within {timeout_s}s: {last_err}")


def _get_summary(ctx, pipeline_name, exec_id):
    cp = ctx.client("codepipeline")
    resp = cp.list_pipeline_executions(pipelineName=pipeline_name, maxResults=100)
    for summary in resp.get("pipelineExecutionSummaries", []):
        if summary["pipelineExecutionId"] == exec_id:
            return summary
    return None


def _poll_until_summary_visible(ctx, pipeline_name, exec_id, timeout_s=30.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summary = _get_summary(ctx, pipeline_name, exec_id)
        if summary is not None:
            return summary
        time.sleep(interval_s)
    raise AssertionError(f"pipelineExecutionId={exec_id} never appeared in ListPipelineExecutions within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
