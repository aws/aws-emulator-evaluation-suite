"""create-user-import-job-untrusted-role-accepted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-user-import-job-untrusted-role-accepted"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_LENIENT_PASSWORD_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}
_POOL_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _err(fn):
    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")


def _new_pool(ctx, c, **kwargs):
    kwargs.setdefault("Policies", _LENIENT_PASSWORD_POLICY)
    kwargs.setdefault("UserPoolTags", _POOL_TAGS)
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"), **kwargs
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_import_log_groups(ctx, pool_id))
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    return pool_id


def _delete_role(iam, role_name):
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    iam.delete_role(RoleName=role_name)


def _new_import_role(ctx, trusted_service):
    """Create an IAM role trusted by ``trusted_service`` with CloudWatch Logs write permission.
    Passing a service OTHER than cognito-idp.amazonaws.com produces a role Cognito cannot assume."""
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-import-role-")
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
        Tags=[{"Key": k, "Value": v} for k, v in _POOL_TAGS.items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))
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


def _create_import_job_with_retry(c, pool_id, job_name, role_arn, timeout_s=60.0):
    """Create the job, polling past a transient PreconditionNotMetException while the new IAM role
    propagates, rather than sleeping a fixed guess."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return c.create_user_import_job(
                JobName=job_name, UserPoolId=pool_id, CloudWatchLogsRoleArn=role_arn
            )["UserImportJob"]
        except c.exceptions.PreconditionNotMetException as exc:
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"CreateUserImportJob never succeeded within {timeout_s}s: {last_err}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateUserImportJob does not validate the CloudWatchLogsRoleArn trust up front: a role
    trusting ec2.amazonaws.com instead of cognito-idp is accepted, the job is in the Created
    state, and it appears in ListUserImportJobs."""
    c = ctx.client("cognito-idp")
    pool_id = _new_pool(ctx, c)
    untrusted_role_arn = _new_import_role(ctx, trusted_service="ec2.amazonaws.com")

    job = _create_import_job_with_retry(
        c, pool_id, ctx.unique_name("sim2real-behav-import-"), untrusted_role_arn
    )
    assert job.get("Status") == "Created", f"expected a newly-created job in Created state, got {job}"
    job_id = job["JobId"]

    jobs = c.list_user_import_jobs(UserPoolId=pool_id, MaxResults=10)["UserImportJobs"]
    assert any(j["JobId"] == job_id for j in jobs), (
        f"the accepted CreateUserImportJob must appear in ListUserImportJobs: {jobs}"
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
