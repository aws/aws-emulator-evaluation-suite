"""user-import-job-start-wrong-state-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "user-import-job-start-wrong-state-rejected"
GROUP = "state-machine"
SERVICES = ["cognito-idp"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """StartUserImportJob on a job already started fails with PreconditionNotMetException and its exact
    message, while a freshly created job starts and both jobs stop when asked."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-importneg-pool-"),
        UserPoolTags={"sim2real:managed": "true"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_import_log_groups(ctx, pool_id))
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    role_arn = _create_import_role(ctx)
    header = idp.get_csv_header(UserPoolId=pool_id)["CSVHeader"]
    job_id = _create_import_job_with_retry(ctx, pool_id, role_arn, header)["JobId"]

    _start_import_job_with_retry(ctx, pool_id, job_id)

    code, message = _error(lambda: idp.start_user_import_job(UserPoolId=pool_id, JobId=job_id))
    assert code == "PreconditionNotMetException", (
        f"expected StartUserImportJob on an already-Pending/InProgress job to be rejected "
        f"with PreconditionNotMetException, got {code!r}"
    )
    assert message == f"{job_id} is not in the created state.", message

    idp.stop_user_import_job(UserPoolId=pool_id, JobId=job_id)
    stopped = _poll_until(
        lambda: idp.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"],
        lambda j: j["Status"] == "Stopped",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert stopped["Status"] == "Stopped", f"expected Stopped, got {stopped['Status']!r}"

    # positive control: StartUserImportJob succeeds again once a job is in a startable state.
    # Restarting the *same* job after StopUserImportJob is not reliably resumable for a
    # zero-row job on real Cognito (the import can settle into a state that keeps rejecting
    # Start with PreconditionNotMetException indefinitely, not just during a brief propagation
    # window), so the meaningful positive control here is that a freshly-created job -- which
    # is unambiguously in the "Created" startable state -- can be started right away.
    new_job_id = _create_import_job_with_retry(ctx, pool_id, role_arn, header)["JobId"]
    restarted = _start_import_job_with_retry(ctx, pool_id, new_job_id)
    assert restarted["Status"] in ("Pending", "InProgress"), (
        f"expected the mutating StartUserImportJob call to report Pending/InProgress, "
        f"got {restarted['Status']!r}"
    )

    # terminal read: an independent DescribeUserImportJob call (not the mutating
    # StartUserImportJob response) must also see the job as started.
    described = idp.describe_user_import_job(UserPoolId=pool_id, JobId=new_job_id)["UserImportJob"]
    assert described["Status"] in ("Pending", "InProgress"), (
        f"expected an independent DescribeUserImportJob read to confirm the freshly-started "
        f"job is Pending/InProgress, got {described['Status']!r}"
    )
    # Wait for the second job to actually settle into Stopped before returning: Cognito can
    # reject DeleteUserPool while a stop is still propagating ("Stopping"), which would leak
    # the pool through cleanup rather than fail the check body.
    idp.stop_user_import_job(UserPoolId=pool_id, JobId=new_job_id)
    stopped_new = _poll_until(
        lambda: idp.describe_user_import_job(UserPoolId=pool_id, JobId=new_job_id)["UserImportJob"],
        lambda j: j["Status"] == "Stopped",
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert stopped_new["Status"] == "Stopped", f"expected Stopped, got {stopped_new['Status']!r}"


def _create_import_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cognito-importneg-")
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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
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
                "Resource": "*",
            }
        ],
    }
    policy_name = "sim2real-cognito-importneg-logs"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_import_job_with_retry(ctx, pool_id, role_arn, header, attempts=6, delay_s=5.0):
    from botocore.exceptions import ClientError

    idp = ctx.client("cognito-idp")
    last_err = None
    for _ in range(attempts):
        try:
            job = idp.create_user_import_job(
                JobName=ctx.unique_name("sim2real-importneg-job-"),
                UserPoolId=pool_id,
                CloudWatchLogsRoleArn=role_arn,
            )["UserImportJob"]
            _upload_csv(ctx, job["PreSignedUrl"], header)
            return job
        except ClientError as err:
            if err.response["Error"]["Code"] != "PreconditionNotMetException":
                raise
            last_err = err
            time.sleep(delay_s)
    raise AssertionError(f"CreateUserImportJob never succeeded (IAM propagation?): {last_err}")


def _start_import_job_with_retry(ctx, pool_id, job_id, attempts=18, delay_s=10.0):
    """StartUserImportJob re-validates the CloudWatch Logs role's permissions, and that
    check can still fail with PreconditionNotMetException for a while after the role's
    policy was created due to IAM propagation delay; retry with a generous budget (up to a
    few minutes) until it clears rather than assuming propagation finishes quickly."""
    from botocore.exceptions import ClientError

    idp = ctx.client("cognito-idp")
    last_err = None
    for _ in range(attempts):
        try:
            return idp.start_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"]
        except ClientError as err:
            if err.response["Error"]["Code"] != "PreconditionNotMetException":
                raise
            last_err = err
            time.sleep(delay_s)
    raise AssertionError(f"StartUserImportJob never succeeded (IAM propagation?): {last_err}")


def _upload_csv(ctx, presigned_url, header):
    """StartUserImportJob requires a CSV to have been uploaded to the job's pre-signed
    URL first; upload a header-only (zero-row) CSV so the job is startable. The bucket
    behind the pre-signed URL enforces SSE-KMS, so the PUT must carry the matching
    x-amz-server-side-encryption header or S3 returns 403 Forbidden."""
    import urllib.request

    # The URL is presigned, so its signature covers the host: send the route headers.
    url, route_headers = ctx.endpoint_route(presigned_url)
    body = (",".join(header) + "\n").encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="PUT",
        headers={"x-amz-server-side-encryption": "aws:kms", **route_headers},
    )
    with urllib.request.urlopen(req, timeout=30, context=_ssl_context(ctx.http_verify)) as resp:
        resp.read()


def _ssl_context(verify):
    """An SSLContext honouring ``ctx.http_verify``: True, False, or a CA bundle path."""
    import ssl

    if verify is False:
        return ssl._create_unverified_context()
    return ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)


def _error(fn):
    """(code, message) of the expected refusal; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


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
