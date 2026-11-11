"""e2e-user-import-job-csv-header-to-active-users."""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-user-import-job-csv-header-to-active-users"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A user import job built on GetCSVHeader's columns reaches Succeeded with one imported user in
    RESET_REQUIRED, who becomes CONFIRMED after AdminSetUserPassword and then signs in with tokens."""
    cognito = ctx.client("cognito-idp")
    iam = ctx.client("iam")
    sts = ctx.client("sts")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-pool-"),
        AutoVerifiedAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_import_log_groups(ctx, pool_id))
    ctx.on_cleanup(lambda: _safe_delete_pool(cognito, pool_id))

    role_arn = _create_import_role(ctx, iam, sts.get_caller_identity()["Account"], ctx.region)

    header = cognito.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    # The password_hash column (from the password-hash-import feature) must be entirely
    # absent from the file when the job doesn't specify PasswordHashingAlgorithm — merely
    # leaving its value blank still trips "CSV file contains a password_hash column, but
    # no passwordHashingAlgorithm was specified".
    header = [col for col in header if "password_hash" not in col]
    username = ctx.unique_name("sim2real-import-")

    row_values = {
        "cognito:username": username,
        "email": f"{username}@example.com",
        "email_verified": "TRUE",
    }
    csv_body = _build_csv(header, [row_values])

    job = _create_import_job_with_retry(cognito, pool_id, ctx.unique_name("sim2real-job-"), role_arn)
    job_id = job["JobId"]
    _upload_csv(ctx, job["PreSignedUrl"], csv_body)

    _start_import_job_with_retry(cognito, pool_id, job_id)
    final_status = _poll_until(
        lambda: cognito.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"],
        lambda job_desc: job_desc["Status"] in ("Succeeded", "Failed", "Stopped", "Expired"),
        timeout_s=240.0,
        interval_s=5.0,
    )
    assert final_status["Status"] == "Succeeded", (
        f"import job did not succeed: status={final_status.get('Status')!r} "
        f"completion={final_status.get('CompletionMessage')!r} "
        f"imported={final_status.get('ImportedUsers')} "
        f"failed={final_status.get('FailedUsers')} "
        f"skipped={final_status.get('SkippedUsers')}"
    )
    assert final_status["ImportedUsers"] == 1, (
        f"expected 1 imported user, job reported {final_status['ImportedUsers']!r}"
    )

    admin_user = cognito.admin_get_user(UserPoolId=pool_id, Username=username)
    assert admin_user["UserStatus"] == "RESET_REQUIRED", (
        f"expected RESET_REQUIRED after import, got {admin_user['UserStatus']!r}"
    )

    password = "Sim2Real123!"
    cognito.admin_set_user_password(
        UserPoolId=pool_id, Username=username, Password=password, Permanent=True
    )
    status_after_password = cognito.admin_get_user(UserPoolId=pool_id, Username=username)["UserStatus"]
    assert status_after_password == "CONFIRMED", (
        f"expected CONFIRMED after AdminSetUserPassword(Permanent=True), got {status_after_password!r}"
    )

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id,
        ClientName=ctx.unique_name("sim2real-client-"),
        ExplicitAuthFlows=["ALLOW_ADMIN_USER_PASSWORD_AUTH"],
        GenerateSecret=False,
    )["UserPoolClient"]["ClientId"]

    login = cognito.admin_initiate_auth(
        UserPoolId=pool_id,
        ClientId=client_id,
        AuthFlow="ADMIN_USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": username, "PASSWORD": password},
    )
    assert login["AuthenticationResult"]["AccessToken"], (
        f"expected a non-empty AccessToken authenticating the imported user, got {login['AuthenticationResult']!r}"
    )


def _create_import_role(ctx, iam, account_id: str, region: str) -> str:
    role_name = ctx.unique_name("sim2real-cognito-import-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cognito-idp.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))

    logs_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:DescribeLogStreams",
                    "logs:PutLogEvents",
                ],
                "Resource": [f"arn:aws:logs:{region}:{account_id}:log-group:/aws/cognito/*"],
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="cognito-import-logs", PolicyDocument=json.dumps(logs_policy)
    )
    return role["Arn"]


def _safe_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="cognito-import-logs")
    except iam.exceptions.NoSuchEntityException:
        pass
    try:
        iam.delete_role(RoleName=role_name)
    except iam.exceptions.NoSuchEntityException:
        pass


def _safe_delete_pool(cognito, pool_id: str) -> None:
    try:
        cognito.delete_user_pool(UserPoolId=pool_id)
    except cognito.exceptions.ResourceNotFoundException:
        pass


def _build_csv(header: list[str], rows: list[dict[str, str]]) -> bytes:
    lines = [",".join(header)]
    for row in rows:
        lines.append(",".join(row.get(col, "") for col in header))
    return ("\n".join(lines) + "\n").encode("utf-8")


def _create_import_job_with_retry(cognito, pool_id: str, job_name: str, role_arn: str, timeout_s: float = 90.0):
    # IAM role trust/permissions can take a short while to propagate; Cognito validates
    # the role at CreateUserImportJob time and raises PreconditionNotMetException until
    # it does. Poll the actual create call rather than sleeping a fixed guess.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cognito.create_user_import_job(
                JobName=job_name, UserPoolId=pool_id, CloudWatchLogsRoleArn=role_arn
            )["UserImportJob"]
        except cognito.exceptions.PreconditionNotMetException as exc:
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"CreateUserImportJob never succeeded (role propagation?): {last_exc}")


def _start_import_job_with_retry(cognito, pool_id: str, job_id: str, timeout_s: float = 180.0) -> None:
    # Cognito re-validates the CloudWatch Logs role (by attempting to assume it and
    # write a log stream) at StartUserImportJob time too, and IAM role propagation can
    # still be incomplete even after CreateUserImportJob already succeeded. Retry the
    # actual start call rather than assuming a fixed grace period is enough.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cognito.start_user_import_job(UserPoolId=pool_id, JobId=job_id)
            return
        except cognito.exceptions.PreconditionNotMetException as exc:
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"StartUserImportJob never succeeded (role propagation?): {last_exc}")


def _upload_csv(ctx, presigned_url: str, body: bytes) -> None:
    _url, _route = ctx.endpoint_route(presigned_url)
    req = urllib.request.Request(
        _url,
        data=body,
        method="PUT",
        headers={**({"x-amz-server-side-encryption": "aws:kms", "Content-Type": "text/csv"}), **_route},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        assert resp.status == 200, f"CSV upload failed with status {resp.status}"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


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
