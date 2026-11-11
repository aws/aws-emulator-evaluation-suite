"""user-import-job-start-without-csv-rejected."""
from __future__ import annotations

import json
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-import-job-start-without-csv-rejected"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:endpoint", "plane:control", "plane:data")
def run(ctx) -> None:
    """StartUserImportJob before the CSV is uploaded fails with PreconditionNotMetException and its exact
    message and the job stays Created; after uploading the CSV the same Start moves it to Pending or
    InProgress."""
    cognito = ctx.client("cognito-idp")
    role_arn = _create_import_role(ctx)
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-pool-"),
        AutoVerifiedAttributes=["email"],
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_import_log_groups(ctx, pool_id))
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    job = _create_import_job_with_retry(cognito, ctx, pool_id, role_arn)
    job_id = job["JobId"]
    presigned_url = job["PreSignedUrl"]
    assert job["Status"] == "Created", job["Status"]

    error = _error_result(lambda: cognito.start_user_import_job(UserPoolId=pool_id, JobId=job_id))
    code = error["Error"]["Code"]
    assert code == "PreconditionNotMetException", f"expected PreconditionNotMetException, got {code}"
    message = error["Error"].get("Message")
    assert message == f"No csv file was uploaded for {job_id}", message

    # the job must remain in Created state after the rejected start attempt
    still = cognito.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"]
    assert still["Status"] == "Created", f"rejected Start must not mutate job state, got {still['Status']}"

    # restore: upload the CSV the precondition demanded, then the identical Start call
    # succeeds -- proving the rejection above was specifically about the missing CSV.
    header = cognito.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    _upload_csv(ctx, presigned_url, header)
    started = _start_import_job_with_retry(cognito, pool_id, job_id)
    ctx.on_cleanup(lambda: _ignore_errors(lambda: cognito.stop_user_import_job(UserPoolId=pool_id, JobId=job_id)))
    assert started["Status"] in ("Pending", "InProgress"), (
        f"expected Start to succeed once the CSV is uploaded, got {started['Status']}"
    )


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
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                    "logs:DescribeLogStreams",
                ],
                "Resource": "arn:aws:logs:*:*:*",
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(logs_policy))
    ctx.on_cleanup(
        lambda: _ignore_errors(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    )
    return role_arn


def _create_import_job_with_retry(cognito, ctx, pool_id: str, role_arn: str, timeout_s: float = 60.0):
    """IAM role trust/permissions are eventually consistent; poll past a transient
    PreconditionNotMetException instead of an unconditional sleep."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    job_name = ctx.unique_name("sim2real-import-").replace("-", "")[:20]
    while time.monotonic() < deadline:
        try:
            return cognito.create_user_import_job(
                JobName=job_name, UserPoolId=pool_id, CloudWatchLogsRoleArn=role_arn
            )["UserImportJob"]
        except cognito.exceptions.PreconditionNotMetException as exc:
            last_err = exc
            time.sleep(5.0)
    raise AssertionError(f"CreateUserImportJob never succeeded within {timeout_s}s: {last_err}")


def _start_import_job_with_retry(cognito, pool_id: str, job_id: str, timeout_s: float = 90.0):
    """StartUserImportJob is where Cognito actually assumes the role; poll past a transient
    PreconditionNotMetException from IAM propagation rather than assuming it clears quickly."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cognito.start_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"]
        except cognito.exceptions.PreconditionNotMetException as exc:
            last_err = exc
            time.sleep(5.0)
    raise AssertionError(f"StartUserImportJob never succeeded within {timeout_s}s: {last_err}")


def _upload_csv(ctx, presigned_url: str, header) -> None:
    body = (",".join(header) + "\n").encode("utf-8")
    _url, _route = ctx.endpoint_route(presigned_url)
    req = urllib.request.Request(
        _url,
        data=body,
        method="PUT",
        headers={**({"x-amz-server-side-encryption": "aws:kms"}), **_route},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        if resp.status not in (200, 201, 204):
            raise AssertionError(f"CSV upload to pre-signed URL failed with status {resp.status}")


def _ignore_errors(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _error_result(fn):
    """Call fn(); return its botocore error response. An unexpected SUCCESS raises, because a target
    that accepts a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected StartUserImportJob to be rejected, but it SUCCEEDED and returned {result!r}")


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
