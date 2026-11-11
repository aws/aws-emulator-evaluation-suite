"""job-poll-visibility-timeout-requeue."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "job-poll-visibility-timeout-requeue"
GROUP = "visibility-timeout-ttl"
SERVICES = ["codepipeline"]


# timing:real-time — visibility: 49 s
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An unacknowledged PollForJobs job is redelivered by a later poll, can then be acknowledged
    (InProgress), and completing it dispatches the Build stage's job."""
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
    cp.start_pipeline_execution(name=pipeline_name)

    first_jobs = _poll_until(
        lambda: cp.poll_for_jobs(actionTypeId=src_type, maxBatchSize=1).get("jobs", []),
        lambda j: len(j) > 0,
        timeout_s=60,
        interval_s=3,
    )
    job_id = first_jobs[0]["id"]

    # Bounded poll: CodePipeline publishes no fixed redelivery latency.
    redelivered = _poll_until(
        lambda: cp.poll_for_jobs(actionTypeId=src_type, maxBatchSize=1).get("jobs", []),
        lambda j: any(job["id"] == job_id for job in j),
        timeout_s=60,
        interval_s=3,
    )
    latest_nonce = next(job["nonce"] for job in redelivered if job["id"] == job_id)

    ack = cp.acknowledge_job(jobId=job_id, nonce=latest_nonce)
    assert ack["status"] == "InProgress", ack

    # Write the declared output artifact where GetJobDetails says, as a job worker would.
    s3 = ctx.client("s3")
    details = cp.get_job_details(jobId=job_id)["jobDetails"]
    assert details["id"] == job_id, details
    for artifact in details["data"].get("outputArtifacts", []):
        loc = (artifact.get("location") or {}).get("s3Location")
        if loc:
            s3.put_object(Bucket=loc["bucketName"], Key=loc["objectKey"], Body=_dummy_zip_bytes())

    cp.put_job_success_result(
        jobId=job_id, currentRevision={"revision": "1", "changeIdentifier": _short_id()}
    )
    # A dispatched Build job is a more reliable signal than GetPipelineState's cached status.
    build_jobs = _poll_until(
        lambda: cp.poll_for_jobs(actionTypeId=build_type, maxBatchSize=1).get("jobs", []),
        lambda j: len(j) > 0,
        timeout_s=120,
        interval_s=4,
    )
    build_job_id = build_jobs[0]["id"]
    build_details = cp.get_job_details(jobId=build_job_id)["jobDetails"]
    assert build_details["data"]["actionTypeId"] == build_type, build_details["data"]["actionTypeId"]
    build_stage = build_details["data"]["pipelineContext"]["stage"]["name"]
    assert build_stage == "Build", build_stage


def _dummy_zip_bytes() -> bytes:
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("artifact.txt", "sim2real-behavioral-test-artifact")
    return buf.getvalue()




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
        # us-east-1 rejects an explicit LocationConstraint for its own region.
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

    last_err: Exception | None = None
    for _ in range(6):
        try:
            # retries absorb IAM role-propagation lag before CodePipeline can assume it
            cp.create_pipeline(pipeline=pipeline_def, tags=[{"key": "sim2real", "value": CHECK}])
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
