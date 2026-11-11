"""create-user-import-job-missing-trust-policy-rejected."""
from __future__ import annotations

import json
import time
import urllib.request

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-user-import-job-missing-trust-policy-rejected"
GROUP = "representation"
SERVICES = ["cognito-idp"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-badimport"}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """CreateUserImportJob accepts a CloudWatchLogsRoleArn not trusting cognito-idp, but
    StartUserImportJob is refused with PreconditionNotMetException for longer than a trusted role's
    propagation window, and succeeds once that same role's trust policy is fixed in place."""
    cognito = ctx.client("cognito-idp")
    iam = ctx.client("iam")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-badimport-pool-"),
        UserPoolTags=_TAGS,
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_import_log_groups(ctx, pool_id))
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))
    header = cognito.get_csv_header(UserPoolId=pool_id)["CSVHeader"]

    # --- positive control: a role correctly trusted by cognito-idp.amazonaws.com starts fine,
    # once IAM propagation clears. Its clearing time L calibrates how long we hold the negative.
    good_role_arn, _ = _create_import_role(ctx, iam, "sim2real-badimport-goodrole-", "cognito-idp.amazonaws.com")
    good_job_id, good_presigned_url = _create_job_with_retry(ctx, cognito, pool_id, good_role_arn, "sim2real-badimport-goodjob-")
    _upload_csv(ctx, good_presigned_url, header)

    t0 = time.monotonic()
    _start_with_retry(cognito, pool_id, good_job_id, deadline=t0 + 120.0, interval_s=5.0)
    positive_control_latency_s = time.monotonic() - t0
    cognito.stop_user_import_job(UserPoolId=pool_id, JobId=good_job_id)
    ctx.on_cleanup(lambda: _try_stop(cognito, pool_id, good_job_id))

    # --- break exactly one thing: same shape of role and job, trust policy points at ec2 instead.
    bad_role_arn, bad_role_name = _create_import_role(ctx, iam, "sim2real-badimport-badrole-", "ec2.amazonaws.com")
    bad_job_id, bad_presigned_url = _create_job_with_retry(ctx, cognito, pool_id, bad_role_arn, "sim2real-badimport-badjob-")
    _upload_csv(ctx, bad_presigned_url, header)
    ctx.on_cleanup(lambda: _try_stop(cognito, pool_id, bad_job_id))

    hold_s = max(3.0 * positive_control_latency_s, 30.0)
    deadline = time.monotonic() + hold_s
    attempts = 0
    while time.monotonic() < deadline:
        attempts += 1
        err = _error(lambda: cognito.start_user_import_job(UserPoolId=pool_id, JobId=bad_job_id))
        code = err.get("Code")
        assert code == "PreconditionNotMetException", (
            f"expected the untrusted-role job's Start to stay rejected with PreconditionNotMetException "
            f"for >= {hold_s:.0f}s (3x the {positive_control_latency_s:.1f}s a correctly-trusted role took "
            f"to clear on this same wiring), got {code!r} on attempt {attempts}"
        )
        expected = "The configured Cloudwatch Logs Role is missing permissions or has an invalid trust policy."
        assert err.get("Message") == expected, (err.get("Message"), expected)
        time.sleep(5.0)
    assert attempts >= 2, f"held the window for only {attempts} attempt(s), too few to mean anything"

    described = cognito.describe_user_import_job(UserPoolId=pool_id, JobId=bad_job_id)["UserImportJob"]
    assert described["Status"] == "Created", (
        f"the untrusted-role job must never have advanced past Created, got {described['Status']!r}"
    )

    # --- restore: fix the SAME role's trust policy in place, no new role or job, then demand
    # the identical StartUserImportJob call now succeeds.
    fixed_trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "cognito-idp.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.update_assume_role_policy(RoleName=bad_role_name, PolicyDocument=json.dumps(fixed_trust))

    restored = _start_with_retry(cognito, pool_id, bad_job_id, deadline=time.monotonic() + 120.0, interval_s=5.0)
    assert restored["Status"] in ("Pending", "InProgress"), (
        f"expected the same job to start once its role's trust policy was fixed, got {restored['Status']!r}"
    )



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
        assert 200 <= resp.status < 300, f"CSV upload to presigned URL failed with status {resp.status}"


def _try_stop(cognito, pool_id: str, job_id: str) -> None:
    """Stop the job; accept already-gone, and a refusal for a job that is not running."""
    try:
        cognito.stop_user_import_job(UserPoolId=pool_id, JobId=job_id)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        if code == "PreconditionNotMetException":
            job = cognito.describe_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"]
            if job["Status"] not in ("Pending", "InProgress", "Stopping"):
                return
        raise


def _error(fn):
    """The botocore Error dict of the expected refusal; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_import_role(ctx, iam, prefix: str, trusted_service: str):
    role_name = ctx.unique_name(prefix)
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": trusted_service},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.tag_role(RoleName=role_name, Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()])

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
            "Resource": "*",
        }],
    }
    policy_name = ctx.unique_name(prefix + "policy-")
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"], role_name


def _create_job_with_retry(ctx, cognito, pool_id: str, role_arn: str, prefix: str, timeout_s: float = 60.0):
    """Create the job, polling past a transient PreconditionNotMetException from IAM propagation.
    Returns (job_id, presigned_url); only CreateUserImportJob returns the presigned URL."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    job_name = ctx.unique_name(prefix)
    while time.monotonic() < deadline:
        try:
            job = cognito.create_user_import_job(
                JobName=job_name, UserPoolId=pool_id, CloudWatchLogsRoleArn=role_arn
            )["UserImportJob"]
            return job["JobId"], job["PreSignedUrl"]
        except cognito.exceptions.PreconditionNotMetException as exc:
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"CreateUserImportJob never succeeded within {timeout_s}s: {last_err}")


def _start_with_retry(cognito, pool_id: str, job_id: str, deadline: float, interval_s: float):
    last_err = None
    while time.monotonic() < deadline:
        try:
            return cognito.start_user_import_job(UserPoolId=pool_id, JobId=job_id)["UserImportJob"]
        except cognito.exceptions.PreconditionNotMetException as exc:
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"StartUserImportJob never cleared before its deadline: {last_err}")


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
