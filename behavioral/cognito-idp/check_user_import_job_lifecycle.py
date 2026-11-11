"""user-import-job-lifecycle."""
from __future__ import annotations

import json
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-import-job-lifecycle"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUserImportJob -> Created; Start -> Pending/InProgress; Stop -> Stopping/Stopped
    (or Succeeded, if the single-row CSV already finished importing before Stop landed)."""
    cognito = ctx.client("cognito-idp")
    role_arn = _create_import_role(ctx)
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        AutoVerifiedAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_import_log_groups(ctx, pool_id))
    ctx.on_cleanup(lambda: _delete_pool_with_retry(cognito, pool_id))

    job = _retry_create_import_job(
        cognito,
        pool_id,
        ctx.unique_name("sim2real-import-").replace("-", "")[:20],
        role_arn,
    )
    job_id = job["JobId"]
    assert job["Status"] == "Created"

    described = cognito.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"]
    assert described["Status"] == "Created"

    ids = {j["JobId"] for j in cognito.list_user_import_jobs(UserPoolId=pool_id, MaxResults=10)["UserImportJobs"]}
    assert job_id in ids

    headers = cognito.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    assert "email" in headers and "email_verified" in headers

    row = {h: "" for h in headers}
    row["email"] = "sim2real-behav-import@example.com"
    row["email_verified"] = "TRUE"
    row["cognito:mfa_enabled"] = "FALSE"
    csv_body = ",".join(headers) + "\n" + ",".join(row[h] for h in headers) + "\n"
    _upload_csv(ctx, job["PreSignedUrl"], csv_body)

    started = _retry_start_import_job(cognito, pool_id, job_id)
    assert started["Status"] in ("Pending", "InProgress"), started["Status"]

    # Stop immediately: Pending and InProgress are both stoppable states.
    stopped = cognito.stop_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"]
    assert stopped["Status"] in ("Stopping", "Stopped", "Succeeded"), stopped["Status"]

    final = _poll_until(
        lambda: cognito.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"],
        lambda j: j["Status"] in ("Stopped", "Succeeded", "Failed"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert final["Status"] in ("Stopped", "Succeeded", "Failed"), final["Status"]


def _create_import_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-import-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "cognito-idp.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _ignore_errors(lambda: iam.delete_role(RoleName=role_name)))

    policy_name = "sim2real-behav-import-logs"
    logs_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:log-group:/aws/cognito/*",
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(logs_policy))
    ctx.on_cleanup(
        lambda: _ignore_errors(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )
    return role_arn


def _delete_pool_with_retry(cognito, pool_id, timeout_s=45.0) -> None:
    """DeleteUserPool can reject with UserImportInProgressException for a short window even
    after DescribeUserImportJob already reports a terminal status -- the pool-level import
    flag and the per-job status converge on slightly different schedules. Bounded retry."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cognito.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "UserImportInProgressException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _retry_create_import_job(cognito, pool_id, job_name, role_arn, timeout_s=30.0):
    """Bounded poll for IAM role/trust-policy propagation lag on a freshly created role."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cognito.create_user_import_job(
                JobName=job_name, UserPoolId=pool_id, CloudWatchLogsRoleArn=role_arn
            )["UserImportJob"]
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            time.sleep(2.0)
    raise last_exc


def _retry_start_import_job(cognito, pool_id, job_id, timeout_s=30.0):
    """Bounded poll for IAM propagation lag on the job's CloudWatchLogsRoleArn."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cognito.start_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"]
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "PreconditionNotMetException":
                raise
            time.sleep(3.0)
    raise last_exc


def _upload_csv(ctx, presigned_url: str, body: str) -> None:
    _url, _route = ctx.endpoint_route(presigned_url)
    req = urllib.request.Request(
        _url,
        data=body.encode("utf-8"),
        method="PUT",
        headers={**({"x-amz-server-side-encryption": "aws:kms"}), **_route},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        if resp.status not in (200, 201):
            raise AssertionError(f"CSV upload failed with status {resp.status}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_import_log_groups(ctx, pool_id):
    """Cognito creates a /aws/cognito/userpools/<pool id>/<pool name> log group for the
    pool's import jobs; the pool is this check's, so every group under its id is too."""
    logs = ctx.client("logs")
    prefix = f"/aws/cognito/userpools/{pool_id}/"
    for page in logs.get_paginator("describe_log_groups").paginate(logGroupNamePrefix=prefix):
        for group in page["logGroups"]:
            try:
                logs.delete_log_group(logGroupName=group["logGroupName"])
            except logs.exceptions.ResourceNotFoundException:
                pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
