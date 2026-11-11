"""code-review-job-reaches-terminal-state."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "code-review-job-reaches-terminal-state"
GROUP = "data-plane"
SERVICES = ["securityagent"]

_TERMINAL = {"COMPLETED", "FAILED", "STOPPED"}

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "securityagent.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A started code review job, read back through BatchGetCodeReviewJobs (never reported not found),
    reaches a terminal status (COMPLETED, FAILED or STOPPED) within 600 s: the job really runs
    asynchronously and is not an instantaneous no-op."""
    sa = ctx.client("securityagent")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    # CreateCodeReview requires serviceRole on real AWS even though the Smithy model marks
    # it optional: an unset one is rejected with ValidationException("Missing required
    # parameter: service_role"). The role must also be registered on the agent space's
    # awsResources.iamRoles before use, or CreateCodeReview rejects it with "Service role ...
    # not found in agent instance IAM roles", so the role is created first and wired in at
    # CreateAgentSpace time.
    role_name = ctx.unique_name("sim2real-behav-secagent-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    bucket, key = _create_source_archive(ctx, s3)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    policy_name = "sim2real-behav-s3-read"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"{bucket_arn}/{key}"},
                    {"Effect": "Allow", "Action": "s3:ListBucket", "Resource": bucket_arn},
                ],
            }
        ),
    )
    # Registered AFTER delete_role so it runs BEFORE it (cleanups are LIFO): an inline
    # policy still attached blocks DeleteRole with DeleteConflict.
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    # Real AWS also rejects an empty `assets`: "Code review must have at least one source
    # code repository", so a real archive is required, not `{}`.
    agent_space_id = sa.create_agent_space(
        name=ctx.unique_name("sim2real-behav-agentspace-"),
        awsResources={"iamRoles": [role_arn], "s3Buckets": [bucket_arn]},
    )["agentSpaceId"]
    ctx.on_cleanup(lambda: sa.delete_agent_space(agentSpaceId=agent_space_id))

    code_review_id = _create_code_review(ctx, sa, agent_space_id, role_arn, bucket, key)
    ctx.on_cleanup(
        lambda: sa.batch_delete_code_reviews(codeReviewIds=[code_review_id], agentSpaceId=agent_space_id)
    )

    started = sa.start_code_review_job(agentSpaceId=agent_space_id, codeReviewId=code_review_id)
    job_id = started["codeReviewJobId"]

    # Never trust started["status"] as the terminal value: that is the mutating call's own response,
    # and a backend that fakes completion synchronously would let it stand in for the independent
    # read this check exists to require. Always poll at least once.
    final_status = "IN_PROGRESS"
    deadline = time.monotonic() + 600.0
    while final_status not in _TERMINAL and time.monotonic() < deadline:
        time.sleep(5.0)
        jobs = sa.batch_get_code_review_jobs(agentSpaceId=agent_space_id, codeReviewJobIds=[job_id])
        # AWS omits `notFound` entirely from the response when it is empty, rather than
        # serializing an empty list.
        not_found = jobs.get("notFound", [])
        assert not_found == [], f"batch_get_code_review_jobs reported job {job_id} not found: {not_found}"
        final_status = jobs["codeReviewJobs"][0]["status"]

    assert final_status in _TERMINAL, (
        f"code review job {job_id} never reached a terminal state, stuck at {final_status!r}"
    )


def _create_source_archive(ctx, s3):
    bucket = ctx.unique_name("sim2real-behav-secagent-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    # us-east-1 is CreateBucket's own special case: the API rejects an explicit
    # LocationConstraint of "us-east-1" rather than accepting it.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, s3, bucket))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("app.py", "print('hello from sim2real behavioral fixture')\n")
    key = "source.zip"
    s3.put_object(Bucket=bucket, Key=key, Body=buf.getvalue())
    return bucket, key


def _empty_and_delete_bucket(ctx, s3, bucket):
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
    s3.delete_bucket(Bucket=bucket)


def _create_code_review(ctx, sa, agent_space_id: str, role_arn: str, bucket: str, key: str) -> str:
    deadline = time.monotonic() + 150.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return sa.create_code_review(
                title=ctx.unique_name("sim2real-behav-codereview-"),
                agentSpaceId=agent_space_id,
                assets={"sourceCode": [{"s3Location": f"s3://{bucket}/{key}"}]},
                serviceRole=role_arn,
            )["codeReviewId"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            if code in ("ValidationException", "AccessDeniedException") and (
                "assume" in msg.lower() or "not authorized" in msg.lower()
            ):
                last_exc = exc
                time.sleep(5.0)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
