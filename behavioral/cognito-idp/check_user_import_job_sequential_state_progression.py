"""user-import-job-sequential-state-progression."""
from __future__ import annotations

import csv
import io
import json
import time
import urllib.request

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "user-import-job-sequential-state-progression"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']


def _error(fn):
    """(code, message) of the expected refusal; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _start_with_retry(fn, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "PreconditionNotMetException":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"{description} never succeeded within {timeout_s}s: {last_err}")


def _poll_until(fn, pred, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description}; last={last!r}")


def _delete_pool_with_retry(c, pool_id, timeout_s=45, interval_s=5):
    """Delete the pool, retrying UserImportInProgressException: DeleteUserPool can briefly lag a
    terminal import job while Cognito finishes its internal teardown."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            c.delete_user_pool(UserPoolId=pool_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "UserImportInProgressException":
                raise RuntimeError(f"pool {pool_id!r} not deleted: {code}: {exc}") from exc
            last_err = exc
            time.sleep(interval_s)
    raise RuntimeError(
        f"pool {pool_id!r} still UserImportInProgressException after retries: {last_err}"
    )


def _new_import_role(ctx, trusted_service="cognito-idp.amazonaws.com"):
    """Create an IAM role trusted by `trusted_service` that may write CloudWatch Logs, for
    CreateUserImportJob; return its ARN and delete it on cleanup."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cip-import-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": trusted_service},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )["Role"]["Arn"]

    def _cleanup_role(_n=role_name):
        try:
            for pname in iam.list_role_policies(RoleName=_n).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=_n, PolicyName=pname)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=_n)

    ctx.on_cleanup(_cleanup_role)
    policy = {
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
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    return arn


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """User import jobs cannot skip states: Stop before Start, a second Start, and Start or Stop
    on a terminal job are each rejected with PreconditionNotMetException without changing the
    job's status."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"})["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_import_log_groups(ctx, pool_id))
    ctx.on_cleanup(lambda _id=pool_id: _delete_pool_with_retry(c, _id))
    role_arn = _new_import_role(ctx)

    job_name = ctx.unique_name("sim2real-behav-cip-import-")
    created = c.create_user_import_job(
        JobName=job_name, UserPoolId=pool_id, CloudWatchLogsRoleArn=role_arn
    )["UserImportJob"]
    job_id = created["JobId"]
    presigned_url = created["PreSignedUrl"]
    assert created["Status"] == "Created", created["Status"]

    desc0 = c.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"]
    assert desc0["Status"] == "Created", desc0["Status"]

    code_stop_before_start, msg_stop_before_start = _error(
        lambda: c.stop_user_import_job(UserPoolId=pool_id, JobId=job_id)
    )
    assert code_stop_before_start == "PreconditionNotMetException", (
        f"expected PreconditionNotMetException stopping a never-started job (Status=Created), got {code_stop_before_start!r}"
    )
    expected = "Job is not running. The specified job has a status of Created"
    assert msg_stop_before_start == expected, (msg_stop_before_start, expected)
    after_bad_stop = c.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"]
    assert after_bad_stop["Status"] == "Created", (
        f"a rejected StopUserImportJob must not mutate job state, got {after_bad_stop['Status']}"
    )

    header = c.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    row = {col: "" for col in header}
    row["cognito:username"] = ctx.unique_name("sim2real-behav-cip-import-user-")
    row["email"] = "imported-user@example.com"
    row["email_verified"] = "TRUE"
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=header)
    writer.writeheader()
    writer.writerow(row)
    csv_bytes = buf.getvalue().encode("utf-8")
    _url, _route = ctx.endpoint_route(presigned_url)
    req = urllib.request.Request(
        _url,
        data=csv_bytes,
        method="PUT",
        headers={**({"x-amz-server-side-encryption": "aws:kms"}), **_route},
    )
    with urllib.request.urlopen(req) as resp:
        assert resp.status in (200, 204), resp.status

    started = _start_with_retry(
        lambda: c.start_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"],
        timeout_s=90,
        interval_s=5,
        description="StartUserImportJob (IAM role propagation)",
    )
    assert started["Status"] in ("Pending", "InProgress"), started["Status"]

    code_double_start, msg_double_start = _error(
        lambda: c.start_user_import_job(UserPoolId=pool_id, JobId=job_id)
    )
    assert code_double_start == "PreconditionNotMetException", (
        f"expected PreconditionNotMetException starting an already-running job, got {code_double_start!r}"
    )
    not_created = f"{job_id} is not in the created state."
    assert msg_double_start == not_created, (msg_double_start, not_created)

    running = _poll_until(
        lambda: c.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"],
        lambda j: j["Status"] in ("InProgress", "Pending", "Stopped", "Failed", "Succeeded"),
        timeout_s=60,
        interval_s=3,
        description="import job reaches a stoppable/terminal state",
    )

    if running["Status"] in ("InProgress", "Pending"):
        stopped = c.stop_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"]
        assert stopped["Status"] in ("Stopping", "Stopped"), stopped["Status"]
        final = _poll_until(
            lambda: c.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"],
            lambda j: j["Status"] in ("Stopped", "Failed", "Succeeded"),
            timeout_s=60,
            interval_s=3,
            description="import job reaches a terminal state",
        )
    else:
        final = running
    assert final["Status"] in ("Stopped", "Failed", "Succeeded"), final["Status"]

    code_stop_after_terminal, msg_stop_after_terminal = _error(
        lambda: c.stop_user_import_job(UserPoolId=pool_id, JobId=job_id)
    )
    assert code_stop_after_terminal == "PreconditionNotMetException", (
        f"expected PreconditionNotMetException stopping a terminal job, got {code_stop_after_terminal!r}"
    )
    expected = f"Job is not running. The specified job has a status of {final['Status']}"
    assert msg_stop_after_terminal == expected, (msg_stop_after_terminal, expected)

    code_start_after_terminal, msg_start_after_terminal = _error(
        lambda: c.start_user_import_job(UserPoolId=pool_id, JobId=job_id)
    )
    assert code_start_after_terminal == "PreconditionNotMetException", (
        f"expected PreconditionNotMetException starting a terminal job, got {code_start_after_terminal!r}"
    )
    assert msg_start_after_terminal == not_created, (msg_start_after_terminal, not_created)

    after_all = c.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"]
    assert after_all["Status"] == final["Status"], (
        "rejected Start/Stop calls on a terminal job must not mutate its status"
    )


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
