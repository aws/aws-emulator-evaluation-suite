"""output-variables-size-exceeded-rejected."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "output-variables-size-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutJobSuccessResult with output variables over the size limit fails with
    OutputVariablesSizeExceededException and its exact message and leaves the action InProgress, so a
    correctly sized call can still complete the job.
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
                    "namespace": "Vars",
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
    cp.start_pipeline_execution(name=pipeline_name)

    job = _poll_for_job(ctx, src_type)
    cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])

    oversized = {"BigVar": "X" * 130000}  # exceeds the 122880-byte combined output variable limit
    code, message = _error_code(
        lambda: cp.put_job_success_result(jobId=job["id"], outputVariables=oversized)
    )
    assert (code, message) == (
        "OutputVariablesSizeExceededException",
        "The total size of all output variables for this action exceeds the limit of 122880 bytes. "
        "Output variables (in bytes): [BigVar: 130006]",
    ), (code, message)

    # effect absent: the job must still be outstanding, not silently completed
    action_state = _action_status(cp, pipeline_name, "Source", "SourceAction")
    assert action_state == "InProgress", action_state

    # positive control: a correctly-sized call on the SAME job succeeds
    s3 = ctx.client("s3")
    details = cp.get_job_details(jobId=job["id"])["jobDetails"]
    for artifact in details["data"].get("outputArtifacts", []):
        loc = (artifact.get("location") or {}).get("s3Location")
        if loc:
            s3.put_object(Bucket=loc["bucketName"], Key=loc["objectKey"], Body=_dummy_zip_bytes())
    cp.put_job_success_result(
        jobId=job["id"],
        outputVariables={"SmallVar": "ok"},
        currentRevision={"revision": "1", "changeIdentifier": _short_id()},
    )
    # Effect present: the completed Source job unblocks the pipeline, and the
    # Build stage's action gets dispatched as a new job.
    build_jobs = _poll_until(
        lambda: cp.poll_for_jobs(actionTypeId=build_type, maxBatchSize=1).get("jobs", []),
        lambda j: len(j) > 0,
        timeout_s=120,
        interval_s=4,
    )
    assert len(build_jobs) > 0, build_jobs


def _dummy_zip_bytes() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("artifact.txt", "sim2real-behavioral-test-artifact")
    return buf.getvalue()


def _action_status(cp, pipeline_name: str, stage_name: str, action_name: str) -> str | None:
    states = cp.get_pipeline_state(name=pipeline_name)["stageStates"]
    for s in states:
        if s["stageName"] == stage_name:
            for a in s.get("actionStates", []):
                if a["actionName"] == action_name:
                    return a.get("latestExecution", {}).get("status")
            return None
    raise AssertionError(f"stage {stage_name} not found in {states}")


def _short_id() -> str:
    return uuid.uuid4().hex[:10]


def _error_code(fn):
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _poll_for_job(ctx, action_type_id: dict) -> dict:
    cp = ctx.client("codepipeline")
    jobs = _poll_until(
        lambda: cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1).get("jobs", []),
        lambda j: len(j) > 0,
        timeout_s=60,
        interval_s=3,
    )
    return jobs[0]


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-art-").lower()
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1 itself.
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
    if pipeline_type == "V2":
        pipeline_def["pipelineType"] = "V2"

    # A freshly created role is not yet assumable everywhere; retry the propagation window
    # instead of a fixed sleep before the first attempt.
    deadline = time.monotonic() + 60
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline_def, tags=[{"key": "sim2real", "value": CHECK}])
            break
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidStructureException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)

    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
