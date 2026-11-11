"""put-job-success-on-already-completed-job-not-permissive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-job-success-on-already-completed-job-not-permissive"
GROUP = "overly-permissive"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutJobFailureResult on a job already completed with PutJobSuccessResult fails with
    InvalidJobStateException and its exact message, the Build stage and action stay Succeeded, and a fresh job
    can still be failed.
    """
    cp = ctx.client("codepipeline")
    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx, bucket)
    _upload_source_zip(ctx, bucket, "source.zip")

    raw = ctx.unique_name("x")
    provider = ("SimBuild" + "".join(ch for ch in raw if ch.isalnum()))[:35]
    category = "Build"
    version = "1"
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version)
    )

    name = ctx.unique_name("sim2real-cp-jobstate-")
    stages = [
        {
            "name": "Source",
            "actions": [
                {
                    "name": "SourceAction",
                    "actionTypeId": {
                        "category": "Source",
                        "owner": "AWS",
                        "provider": "S3",
                        "version": "1",
                    },
                    "configuration": {
                        "S3Bucket": bucket,
                        "S3ObjectKey": "source.zip",
                        "PollForSourceChanges": "false",
                    },
                    "outputArtifacts": [{"name": "SourceOutput"}],
                }
            ],
        },
        {
            "name": "Build",
            "actions": [
                {
                    "name": "BuildAction",
                    "actionTypeId": {
                        "category": category,
                        "owner": "Custom",
                        "provider": provider,
                        "version": version,
                    },
                    "inputArtifacts": [{"name": "SourceOutput"}],
                    "outputArtifacts": [{"name": "BuildOutput"}],
                }
            ],
        },
    ]
    _create_pipeline(ctx, name, role_arn, bucket, stages)
    # CreatePipeline auto-triggers its own initial execution; rely on that rather
    # than calling StartPipelineExecution again, which would just queue a second,
    # superseded execution behind the one already occupying the Build action.

    action_type_id = {
        "category": category,
        "owner": "Custom",
        "provider": provider,
        "version": version,
    }
    job = _poll_for_job(ctx, action_type_id, timeout_s=120)
    job_id = job["id"]
    cp.acknowledge_job(jobId=job_id, nonce=job["nonce"])

    # complete the job successfully -- this is the positive control proving the
    # normal completion path works.
    cp.put_job_success_result(jobId=job_id)
    _wait_for_stage_status(ctx, name, "Build", "Succeeded", timeout_s=240)

    # break exactly one thing: try to flip the outcome of the very same,
    # already-succeeded job to a failure via the opposing terminal API.
    error = _error(
        lambda: cp.put_job_failure_result(
            jobId=job_id,
            failureDetails={"type": "JobFailed", "message": "should be rejected"},
        )
    )
    assert error.get("Code") == "InvalidJobStateException", f"unexpected error: {error!r}"
    expected_message = f"Job with id {job_id} has already terminated"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # effect absent: the stage's recorded outcome is still the original Succeeded,
    # not overwritten or flipped by either rejected call.
    final_state = cp.get_pipeline_state(name=name)
    build_stage = next(s for s in final_state["stageStates"] if s["stageName"] == "Build")
    assert build_stage["latestExecution"]["status"] == "Succeeded", (
        f"expected Succeeded, got {build_stage['latestExecution']['status']}"
    )
    action_status = build_stage["actionStates"][0]["latestExecution"]["status"]
    assert action_status == "Succeeded", f"expected Succeeded, got {action_status}"

    # restore: the rejection above is specific to this terminal job, not a
    # standing block on PutJobFailureResult itself -- a fresh execution's job on
    # the very same pipeline accepts the identical call and the stage flips to
    # Failed, so the earlier rejection cannot be mistaken for "this account
    # rejects every PutJobFailureResult".
    cp.start_pipeline_execution(name=name)
    job2 = _poll_for_job(ctx, action_type_id, timeout_s=120)
    job2_id = job2["id"]
    cp.acknowledge_job(jobId=job2_id, nonce=job2["nonce"])
    cp.put_job_failure_result(
        jobId=job2_id,
        failureDetails={"type": "JobFailed", "message": "expected failure on a fresh job"},
    )
    _wait_for_stage_status(ctx, name, "Build", "Failed", timeout_s=240)
    restored_state = cp.get_pipeline_state(name=name)
    restored_build_stage = next(s for s in restored_state["stageStates"] if s["stageName"] == "Build")
    assert restored_build_stage["latestExecution"]["status"] == "Failed", (
        f"expected Failed, got {restored_build_stage['latestExecution']['status']}"
    )


def _error(fn) -> dict:
    """Call fn and return the botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-jobstate-").lower().replace("_", "-")
    # us-east-1 is S3's one region that rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        objs = s3.list_object_versions(Bucket=bucket)
        to_delete = [
            {"Key": v["Key"], "VersionId": v["VersionId"]}
            for v in objs.get("Versions", []) + objs.get("DeleteMarkers", [])
        ]
        if to_delete:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": to_delete}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _upload_source_zip(ctx, bucket, key):
    s3 = ctx.client("s3")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("README.txt", "sim2real behavioral check artifact")
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())


def _create_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = f"{role_name}-s3"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "s3:*",
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    # IAM roles/policies can take a short time to propagate before another service can
    # assume them: https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if iam.get_role(RoleName=role_name)["Role"]["RoleName"] == role_name:
            break
        time.sleep(1)
    return role["Arn"]


def _create_pipeline(ctx, name, role_arn, bucket, stages, *, timeout_s=60.0, interval_s=5.0):
    cp = ctx.client("codepipeline")
    pipeline = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": bucket},
        "stages": stages,
    }
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            result = cp.create_pipeline(pipeline=pipeline, tags=[{"key": "sim2real", "value": CHECK}])
            ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
            return result
        except ClientError as err:
            # A role that has only just been created can transiently fail role-assumption
            # validation until IAM propagation catches up; a bounded retry on the real
            # dependent call proves propagation rather than guessing how long it takes.
            last_err = err
            if err.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"create_pipeline never succeeded within {timeout_s}s: {last_err}")


def _poll_for_job(ctx, action_type_id, *, timeout_s=120.0, interval_s=3.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        jobs = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1).get("jobs", [])
        if jobs:
            return jobs[0]
        time.sleep(interval_s)
    raise AssertionError(f"no job appeared for {action_type_id} within {timeout_s}s")


def _wait_for_stage_status(ctx, pipeline_name, stage_name, expected_status, *, timeout_s=60.0, interval_s=5.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        state = cp.get_pipeline_state(name=pipeline_name)
        stage = next(s for s in state["stageStates"] if s["stageName"] == stage_name)
        last = stage.get("latestExecution", {}).get("status")
        if last == expected_status:
            return
        time.sleep(interval_s)
    raise AssertionError(f"stage {stage_name} never reached {expected_status}, last saw {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

