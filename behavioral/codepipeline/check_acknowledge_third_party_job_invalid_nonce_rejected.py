"""acknowledge-third-party-job-invalid-nonce-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "acknowledge-third-party-job-invalid-nonce-rejected"
GROUP = "overly-permissive"
SERVICES = ["codepipeline"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """AcknowledgeThirdPartyJob on an unknown job id is rejected with JobNotFoundException;
    AcknowledgeJob with an empty nonce on a real custom-action job is rejected with
    ValidationException, and the same job then acknowledges with its real nonce."""
    cp = ctx.client("codepipeline")

    # Only AWS-vetted partners can register ThirdParty-owned action types, so a real
    # third-party job cannot be provisioned; an unknown job id is the reachable case.
    unknown_job_id = "00000000-0000-0000-0000-000000000000"
    code, message = _error_code(
        lambda: cp.acknowledge_third_party_job(
            jobId=unknown_job_id,
            nonce="bogus-nonce",
            clientToken="bogus-client-token",
        )
    )
    assert (code, message) == ("JobNotFoundException", f"Job with id '{unknown_job_id}' does not exist."), (
        f"expected JobNotFoundException for a nonexistent job id, got {(code, message)!r}"
    )

    # AcknowledgeJob shares AcknowledgeThirdPartyJob's nonce validation and works on a
    # self-service custom action, so it exercises a bad nonce on a job that exists.
    category, provider, version = "Build", ctx.unique_name("Sim2RealBuild-")[:35], "1"
    cp.create_custom_action_type(
        category=category,
        provider=provider,
        version=version,
        inputArtifactDetails={"minimumCount": 1, "maximumCount": 1},
        outputArtifactDetails={"minimumCount": 0, "maximumCount": 0},
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_custom_action_type(category=category, provider=provider, version=version))

    role_arn = _create_pipeline_role(ctx)
    bucket = _create_bucket(ctx, versioning=True)
    ctx.client("s3").put_object(Bucket=bucket, Key="src.txt", Body=b"hello-custom-job")

    name = ctx.unique_name("sim2real-cp-pipe-")
    _create_pipeline_with_retry(
        cp,
        {
            "name": name,
            "roleArn": role_arn,
            "artifactStore": {"type": "S3", "location": bucket},
            "stages": [
                {
                    "name": "Source",
                    "actions": [
                        {
                            "name": "SourceAction",
                            "actionTypeId": {"category": "Source", "owner": "AWS", "provider": "S3", "version": "1"},
                            "configuration": {
                                "S3Bucket": bucket,
                                "S3ObjectKey": "src.txt",
                                "PollForSourceChanges": "false",
                            },
                            "outputArtifacts": [{"name": "SourceArtifact"}],
                        }
                    ],
                },
                {
                    "name": "CustomBuild",
                    "actions": [
                        {
                            "name": "CustomBuildAction",
                            "actionTypeId": {
                                "category": category,
                                "owner": "Custom",
                                "provider": provider,
                                "version": version,
                            },
                            "inputArtifacts": [{"name": "SourceArtifact"}],
                            "configuration": {},
                        }
                    ],
                },
            ],
        },
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: cp.delete_pipeline(name=name))

    cp.start_pipeline_execution(name=name)

    action_type_id = {"category": category, "owner": "Custom", "provider": provider, "version": version}
    job = _poll_until(
        lambda: (cp.poll_for_jobs(actionTypeId=action_type_id, maxBatchSize=1).get("jobs") or [None])[0],
        lambda j: j is not None,
        timeout_s=120,
        interval_s=5,
    )
    assert job is not None, "custom-action job never appeared on the queue"
    job_id, real_nonce = job["id"], job["nonce"]

    # AcknowledgeJob accepts a well-formed but mismatched nonce; an empty one is rejected by
    # input validation (ValidationException). boto3 rejects "" client-side, so parameter
    # validation is disabled to observe the service's verdict.
    from botocore.config import Config

    raw_cp = ctx.client("codepipeline", config=Config(parameter_validation=False))
    code, message = _error_code(lambda: raw_cp.acknowledge_job(jobId=job_id, nonce=""))
    assert (code, message) == (
        "ValidationException",
        "1 validation error detected: Value at 'nonce' failed to satisfy constraint: "
        "Member must have length greater than or equal to 1",
    ), (
        f"unexpected refusal for empty nonce: {(code, message)!r}"
    )

    # Positive control: the rejected call did not consume the job.
    ack = cp.acknowledge_job(jobId=job_id, nonce=real_nonce)
    assert ack["status"] == "InProgress", f"expected InProgress after acknowledging with the real nonce, got {ack['status']!r}"


def _create_pipeline_with_retry(
    cp, pipeline: dict, tags: list[dict] | None = None, attempts: int = 6, delay_s: float = 5.0
) -> dict:
    """CreatePipeline can transiently fail with InvalidStructureException /
    ValidationException while the just-created IAM role's trust policy propagates."""
    from botocore.exceptions import ClientError

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


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _poll_until(probe, predicate, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return None


def _create_pipeline_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "codepipeline.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-cp-policy-")
    policy_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_bucket(ctx, versioning: bool = False) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-").lower()
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    if versioning:
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket))
    return bucket


def _delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
            objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
            if objs:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
