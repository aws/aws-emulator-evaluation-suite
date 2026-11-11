"""poll-for-jobs-lease-expires-and-job-becomes-available-again."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "poll-for-jobs-lease-expires-and-job-becomes-available-again"
GROUP = "visibility-timeout-ttl"
SERVICES = ["codepipeline"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An unacknowledged PollForJobs job is redelivered with a fresh nonce; the stale nonce still
    acknowledges it, after which the fresher nonce is rejected with InvalidNonceException.
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

    cp.start_pipeline_execution(name=pipeline_name)

    first_job = _poll_until(
        lambda: cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1).get("jobs", []),
        lambda jobs: bool(jobs),
        timeout_s=90.0,
        interval_s=3.0,
    )[0]
    stale_nonce = first_job["nonce"]
    job_id = first_job["id"]

    # Never acknowledge it. timeoutInMinutes is only allowed on Manual Approval actions, so the
    # requeue waits out the action's fixed default lease.
    second_job = _poll_until(
        lambda: cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1).get("jobs", []),
        lambda jobs: bool(jobs) and jobs[0]["id"] == job_id and jobs[0]["nonce"] != stale_nonce,
        timeout_s=420.0,
        interval_s=10.0,
    )[0]

    # Redelivery does not invalidate the first-dispatch nonce.
    ack = cp.acknowledge_job(jobId=job_id, nonce=stale_nonce)
    assert ack["status"] == "InProgress", ack["status"]

    # Once acknowledged, the claim is closed: the fresher nonce from the requeue poll is
    # no longer usable against the same (now claimed) job.
    code, message = _error_code(lambda: cp.acknowledge_job(jobId=job_id, nonce=second_job["nonce"]))
    assert (code, message) == ("InvalidNonceException", f"Invalid nonce for job id {job_id}"), (code, message)

    # The rejected second-nonce attempt did not disturb the claim.
    state = cp.get_pipeline_state(name=pipeline_name)
    build_status = next(
        (
            a.get("latestExecution", {}).get("status")
            for s in state.get("stageStates", [])
            if s["stageName"] == "Build"
            for a in s.get("actionStates", [])
            if a["actionName"] == "Build"
        ),
        None,
    )
    assert build_status == "InProgress", build_status

    cp.put_job_success_result(jobId=job_id)


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _zip_bytes() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real behavioral check source artifact")
    return buf.getvalue()


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")
    kwargs = {}
    # us-east-1 rejects an explicit LocationConstraint matching its own default region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
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

    # Bounded retry, not a fixed sleep: CreatePipeline fails transiently while the
    # just-created IAM role's trust policy propagates.
    deadline = time.monotonic() + 60.0
    while True:
        try:
            cp.create_pipeline(pipeline=pipeline)
            break
        except ClientError:
            if time.monotonic() > deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
