"""get-job-details-not-found."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-job-details-not-found"
GROUP = 'error-semantics'
SERVICES = ['codepipeline']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetJobDetails returns the job the check's own pipeline dispatched, while GetJobDetails on a never-issued
    jobId fails with JobNotFoundException and its exact message.
    """
    cp = ctx.client("codepipeline")
    action_type = _create_custom_action_type(ctx, "Source", 0, 0, 1, 1)
    build_type = _create_custom_action_type(ctx, "Build", 1, 1, 0, 1)
    pipeline_name = _create_pipeline(
        ctx,
        [
            {
                "name": "Source",
                "actions": [
                    {
                        "name": "SourceAction",
                        "actionTypeId": action_type,
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
                    }
                ],
            },
        ],
    )
    cp.start_pipeline_execution(name=pipeline_name)
    job = _poll_for_job(ctx, action_type)

    # --- positive control: a real, freshly dispatched job resolves ---
    details = cp.get_job_details(jobId=job["id"])["jobDetails"]
    assert details["id"] == job["id"], details

    # --- negative: an id this account never issued is rejected
    bogus_id = str(uuid.uuid4())
    refusal = _error_code(lambda: cp.get_job_details(jobId=bogus_id))
    assert refusal == ("JobNotFoundException", f"Job with id {bogus_id} does not exist"), refusal


def _error_code(fn):
    """Call fn(); return (code, message) of its refusal. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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


def _short_id() -> str:
    return uuid.uuid4().hex[:10]


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-cp-art-").lower()
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":  # S3 CreateBucket rejects a LocationConstraint equal to us-east-1
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

    # CreatePipeline can race a freshly created role's trust-policy propagation --
    # real AWS reports this specific race as InvalidStructureException naming
    # AssumeRole, not AccessDenied. Retry bounded on exactly that, never blind.
    deadline = time.monotonic() + 90.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            cp.create_pipeline(pipeline=pipeline_def)
            break
        except ClientError as e:
            err = e.response.get("Error", {})
            if err.get("Code") != "InvalidStructureException" or "AssumeRole" not in err.get(
                "Message", ""
            ):
                raise
            last_err = e
            time.sleep(5)
    else:
        raise AssertionError(f"create_pipeline still denied after role propagation wait: {last_err}")

    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
