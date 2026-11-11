"""list-action-executions-chronological-order."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-action-executions-chronological-order"
GROUP = "ordering"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListActionExecutions for a two-stage execution returns two Succeeded records most recent first: Build
    before Source, with non-increasing startTime.
    """
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

    # CreatePipeline triggers an execution automatically -- calling StartPipelineExecution
    # here as well would race a second execution against that auto-triggered one, and
    # poll_for_jobs (which is not execution-scoped) would service whichever job queued
    # first. Observe the auto-triggered execution instead of starting a competing one.
    execution_id = _poll_until(
        lambda: cp.list_pipeline_executions(pipelineName=pipeline_name).get(
            "pipelineExecutionSummaries", []
        ),
        lambda execs: len(execs) >= 1,
        timeout_s=60,
        interval_s=3,
    )[0]["pipelineExecutionId"]

    _drive_job(ctx, src_type)
    _drive_job(ctx, build_type)

    # A record appears in ListActionExecutions as soon as its action starts, but its
    # status lags PutJobSuccessResult by a few seconds while CodePipeline catches the
    # summarized read path up to the write; wait for both records to reach a terminal
    # status, not merely to exist.
    details = _poll_until(
        lambda: cp.list_action_executions(
            pipelineName=pipeline_name,
            filter={"pipelineExecutionId": execution_id},
        )["actionExecutionDetails"],
        lambda d: len(d) >= 2 and all(x["status"] in ("Succeeded", "Failed") for x in d),
        timeout_s=300,
        interval_s=10,
    )

    assert len(details) == 2, details
    # Most-recently-run action (Build, which ran after Source) must be first.
    stage_order = [d["stageName"] for d in details]
    assert stage_order == ["Build", "Source"], stage_order
    start_times = [d["startTime"] for d in details]
    assert start_times[0] >= start_times[1], start_times
    assert all(d["status"] == "Succeeded" for d in details), details


def _short_id() -> str:
    return uuid.uuid4().hex[:10]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-art-").lower()
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)
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
    if pipeline_type == "V2":
        pipeline_def["pipelineType"] = "V2"

    # Bounded retry absorbs IAM role propagation delay: CodePipeline can reject the
    # role as not-yet-assumable for a few seconds after put_role_policy returns.
    last_err: Exception | None = None
    for _ in range(6):
        try:
            cp.create_pipeline(pipeline=pipeline_def)
            break
        except ClientError as e:
            last_err = e
            time.sleep(5)
    else:
        raise last_err  # type: ignore[misc]

    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


def _dummy_zip_bytes() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("artifact.txt", "sim2real-behavioral-test-artifact")
    return buf.getvalue()


def _drive_job(ctx, action_type_id: dict, outcome: str = "success", output_variables: dict | None = None,
                failure_message: str = "boom"):
    cp = ctx.client("codepipeline")
    s3 = ctx.client("s3")
    jobs = _poll_until(
        lambda: cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1).get("jobs", []),
        lambda j: len(j) > 0,
        timeout_s=60,
        interval_s=3,
    )
    job = jobs[0]
    job_id = job["id"]
    nonce = job["nonce"]
    cp.acknowledge_job(jobId=job_id, nonce=nonce)
    if outcome == "success":
        # A real job worker uploads its declared output artifacts to S3 before
        # reporting success; do the same so the stage can genuinely complete.
        details = cp.get_job_details(jobId=job_id)["jobDetails"]
        for artifact in details["data"].get("outputArtifacts", []):
            loc = (artifact.get("location") or {}).get("s3Location")
            if loc:
                s3.put_object(Bucket=loc["bucketName"], Key=loc["objectKey"], Body=_dummy_zip_bytes())
        kwargs: dict[str, Any] = {
            "jobId": job_id,
            "currentRevision": {"revision": "1", "changeIdentifier": _short_id()},
        }
        if output_variables:
            kwargs["outputVariables"] = output_variables
        cp.put_job_success_result(**kwargs)
    else:
        cp.put_job_failure_result(
            jobId=job_id, failureDetails={"type": "JobFailed", "message": failure_message}
        )
    return job


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
