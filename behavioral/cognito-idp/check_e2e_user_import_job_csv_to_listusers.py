"""e2e-user-import-job-csv-to-listusers."""
from __future__ import annotations

import csv
import io
import json
import time
import urllib.request

from behavioral_harness import tags

CHECK = "e2e-user-import-job-csv-to-listusers"
GROUP = "e2e"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A CSV uploaded to a user import job's pre-signed URL and started reaches a terminal status,
    and the imported users are visible with their attributes via ListUsers and AdminGetUser,
    so a job that never processes the file fails."""
    cognito = ctx.client("cognito-idp")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-import-pool-"),
        AutoVerifiedAttributes=["email"],
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_import_log_groups(ctx, pool_id))
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    role_name = ctx.unique_name("sim2real-import-role-")
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = ctx.unique_name("sim2real-import-policy-")
    log_policy = {
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
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(log_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    header = cognito.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    assert "cognito:username" in header, f"CSVHeader missing cognito:username column: {header!r}"
    assert "email" in header, f"CSVHeader missing email column: {header!r}"
    # GetCSVHeader always includes an (optional) password_hash column for the
    # password-hash-import feature; a filled-in but improperly-configured value there
    # is rejected at start time, and this check isn't exercising password-hash import,
    # so drop it and leave those users to import in the normal RESET_REQUIRED state.
    import_header = [col for col in header if "password_hash" not in col.lower()]

    username1 = ctx.unique_name("s2rimport1")
    username2 = ctx.unique_name("s2rimport2")
    rows = [
        {"cognito:username": username1, "email": f"{username1}@example.com", "email_verified": "true"},
        {"cognito:username": username2, "email": f"{username2}@example.com", "email_verified": "true"},
    ]
    csv_bytes = _build_csv(import_header, rows)

    job = _create_import_job_with_retry(cognito, pool_id, role_arn)
    job_id = job["JobId"]
    presigned_url = job["PreSignedUrl"]

    _upload_csv(ctx, presigned_url, csv_bytes)

    _start_import_job_with_retry(cognito, pool_id, job_id)

    final = _poll_until(
        lambda: cognito.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)[
            "UserImportJob"
        ],
        lambda job_state: job_state["Status"] in ("Succeeded", "Failed", "Stopped"),
        timeout_s=240,
        interval_s=10,
    )
    assert final["Status"] == "Succeeded", final.get("CompletionMessage")
    assert final["ImportedUsers"] == 2, f"expected 2 imported users, job reported {final['ImportedUsers']}"
    assert final["FailedUsers"] == 0, f"expected 0 failed users, job reported {final['FailedUsers']}"

    listed = cognito.list_users(UserPoolId=pool_id, Limit=60)["Users"]
    listed_usernames = {u["Username"] for u in listed}
    assert username1 in listed_usernames, f"{username1} not in ListUsers result: {listed_usernames!r}"
    assert username2 in listed_usernames, f"{username2} not in ListUsers result: {listed_usernames!r}"

    fetched = cognito.admin_get_user(UserPoolId=pool_id, Username=username1)
    assert fetched["UserStatus"] == "RESET_REQUIRED", f"expected RESET_REQUIRED, got {fetched['UserStatus']!r}"
    fetched_attrs = {a["Name"]: a["Value"] for a in fetched["UserAttributes"]}
    assert "email" in fetched_attrs, f"imported user missing email attribute: {fetched['UserAttributes']!r}"
    assert fetched_attrs["email"] == f"{username1}@example.com", (
        f"expected email {username1}@example.com, got {fetched_attrs['email']!r}"
    )


def _build_csv(header: list, rows: list) -> bytes:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=header, restval="", extrasaction="raise")
    writer.writeheader()
    for row in rows:
        full_row = {col: row.get(col, "") for col in header}
        writer.writerow(full_row)
    return buf.getvalue().encode("utf-8")


def _upload_csv(ctx, presigned_url: str, csv_bytes: bytes) -> None:
    _url, _route = ctx.endpoint_route(presigned_url)
    req = urllib.request.Request(
        _url,
        data=csv_bytes,
        method="PUT",
        headers={**({"x-amz-server-side-encryption": "aws:kms"}), **_route},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        assert 200 <= resp.status < 300, f"CSV upload failed: {resp.status}"


def _create_import_job_with_retry(cognito, pool_id: str, role_arn: str, timeout_s: float = 30.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return cognito.create_user_import_job(
                JobName=f"sim2realimportjob{int(time.time())}",
                UserPoolId=pool_id,
                CloudWatchLogsRoleArn=role_arn,
            )["UserImportJob"]
        except Exception as exc:  # noqa: BLE001 - retrying on IAM role propagation
            last_exc = exc
            time.sleep(3)
    raise AssertionError(f"CreateUserImportJob never succeeded: {last_exc}")


def _start_import_job_with_retry(cognito, pool_id: str, job_id: str, timeout_s: float = 90.0):
    # StartUserImportJob validates that the CloudWatchLogsRoleArn is actually assumable
    # and has working permissions at start time. A freshly-created role/inline-policy
    # pair can take a while to propagate through IAM, so retry on
    # PreconditionNotMetException rather than treating it as a hard failure.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            cognito.start_user_import_job(UserPoolId=pool_id, JobId=job_id)
            return
        except Exception as exc:  # noqa: BLE001 - retrying on IAM role propagation
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"StartUserImportJob never succeeded: {last_exc}")



def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {value}")


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
