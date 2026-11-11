"""acknowledge-job-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "acknowledge-job-not-found"
GROUP = 'error-semantics'
SERVICES = ['codepipeline']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AcknowledgeJob on a polled job returns InProgress, while AcknowledgeJob with an unknown jobId fails with
    JobNotFoundException and its exact message.
    """
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
    _create_pipeline_with_retry(cp, pipeline, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=pipeline_name))

    action_type_id = {"category": "Source", "owner": "Custom", "provider": source_provider, "version": "1"}
    job = _poll_one_job(ctx, action_type_id)

    # Positive control: AcknowledgeJob on the genuinely issued job succeeds.
    ack = cp.acknowledge_job(jobId=job["id"], nonce=job["nonce"])
    assert ack["status"] == "InProgress", ack
    cp.put_job_success_result(jobId=job["id"])

    # Break: AcknowledgeJob against a jobId that was never issued.
    unknown_job_id = '8208d258-a241-4061-b5c8-84737d488a14'
    code, message = _error_code(lambda: cp.acknowledge_job(jobId=unknown_job_id, nonce='1'))
    assert (code, message) == ("JobNotFoundException", f"Job with id {unknown_job_id} does not exist"), (code, message)


def _error_code(fn):
    """Return (code, message) of the expected refusal; raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _create_artifact_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-art-").lower().replace("_", "-")[:63]
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
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


def _create_custom_action_type(ctx, category, provider, version, in_min, in_max, out_min, out_max):
    cp = ctx.client("codepipeline")
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": in_min, "maximumCount": in_max},
        outputArtifactDetails={"minimumCount": out_min, "maximumCount": out_max},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version))


def _create_pipeline_with_retry(cp, pipeline: dict, tags=None, attempts: int = 6, delay_s: float = 5.0):
    """CreatePipeline can transiently fail with InvalidStructureException /
    ValidationException while the just-created IAM role's trust policy propagates."""
    last_err = None
    for _ in range(attempts):
        try:
            return cp.create_pipeline(pipeline=pipeline, tags=tags or [])
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] in ("InvalidStructureException", "ValidationException"):
                time.sleep(delay_s)
                continue
            raise
    raise last_err


def _poll_one_job(ctx, action_type_id, timeout_s=90.0, interval_s=3.0):
    cp = ctx.client("codepipeline")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1)
        jobs = resp.get("jobs", [])
        if jobs:
            return jobs[0]
        time.sleep(interval_s)
    raise AssertionError(f"no job appeared for actionTypeId={action_type_id} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
