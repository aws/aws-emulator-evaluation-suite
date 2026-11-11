"""limit-exceeded-user-import-job."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "limit-exceeded-user-import-job"
GROUP = 'overly-permissive'
SERVICES = ['cognito-idp']

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
_LENIENT_POLICY = {
    "PasswordPolicy": {
        "MinimumLength": 8,
        "RequireUppercase": False,
        "RequireLowercase": False,
        "RequireNumbers": False,
        "RequireSymbols": False,
    }
}


def _error(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError("real AWS rejects this call, but it SUCCEEDED")


def _retry_throttled(fn, *, max_attempts: int = 8, base_delay: float = 1.0):
    delay = base_delay
    for attempt in range(max_attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "TooManyRequestsException" and attempt < max_attempts - 1:
                time.sleep(delay)
                delay = min(delay * 1.7, 15.0)
                continue
            raise


def _run_concurrent(fns, *, timeout_s=90):
    import concurrent.futures

    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:  # noqa: BLE001
            results[idx] = exc
        resolved.add(idx)

    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _new_import_role(ctx):
    """Create an IAM role trusted by cognito-idp.amazonaws.com with CloudWatch
    Logs write permission, for CreateUserImportJob's CloudWatchLogsRoleArn.
    Registers cleanup. Role propagation is not waited out here -- callers poll
    the actual CreateUserImportJob call, which raises PreconditionNotMetException
    until the role is usable."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-cip-import-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cognito-idp.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]["Arn"]

    def _cleanup_role():
        try:
            for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateUserImportJob past the pool's 1,000-job quota fails with LimitExceededException and its exact
    message, again on a second attempt, and the rejected job name never appears in
    ListUserImportJobs."""
    c = ctx.client("cognito-idp")
    pool_id = c.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cip-pool-"),
        UserPoolTags=_TAGS,
        Policies=_LENIENT_POLICY,
        AutoVerifiedAttributes=["email"],
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: _delete_import_log_groups(ctx, pool_id))
    ctx.on_cleanup(lambda: c.delete_user_pool(UserPoolId=pool_id))
    role_arn = _new_import_role(ctx)

    def create_one() -> None:
        """Create a single import job. Transient throttling and role propagation
        (Cognito raises PreconditionNotMetException until the CloudWatchLogsRoleArn
        it validated at CreateUserImportJob time is actually assumable) are retried
        up to a bounded per-job timeout; LimitExceededException propagates
        immediately."""

        def attempt() -> bool:
            try:
                c.create_user_import_job(
                    JobName=ctx.unique_name("sim2real-behav-cip-imp-"),
                    UserPoolId=pool_id,
                    CloudWatchLogsRoleArn=role_arn,
                )
                return True
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                if code in ("TooManyRequestsException", "PreconditionNotMetException"):
                    return False
                raise

        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            if attempt():
                return
            time.sleep(1.0)

    batch_size = 25
    successes = 0
    limit_error: str | None = None
    limit_message = ""
    deadline = time.monotonic() + 250

    while limit_error is None and time.monotonic() < deadline:
        results = _run_concurrent([create_one for _ in range(batch_size)], timeout_s=90)
        for r in results:
            if isinstance(r, ClientError):
                code = r.response.get("Error", {}).get("Code")
                if code == "LimitExceededException":
                    limit_error = code
                    limit_message = r.response.get("Error", {}).get("Message", "")
                    break
                if code == "InternalErrorException":
                    continue
                raise AssertionError(f"unexpected error creating an import job: {code}")
            elif isinstance(r, BaseException):
                continue
            else:
                successes += 1

    assert limit_error == "LimitExceededException", (
        f"expected LimitExceededException after exceeding the per-pool user-import-job "
        f"quota, but created {successes} jobs without ever hitting it (time budget exhausted)"
    )
    expected_limit_message = "The limit for user pool import jobs is: 1000."
    assert limit_message == expected_limit_message, (
        f"expected message {expected_limit_message!r}, got {limit_message!r}"
    )

    first_page = _retry_throttled(
        lambda: c.list_user_import_jobs(UserPoolId=pool_id, MaxResults=50)
    )
    assert len(first_page["UserImportJobs"]) > 0, (
        "ListUserImportJobs reports zero jobs after successfully creating some"
    )

    over_again_name = ctx.unique_name("sim2real-behav-cip-imp-over-again-")
    repeat_code, repeat_message = _error(
        lambda: _retry_throttled(
            lambda: c.create_user_import_job(
                JobName=over_again_name,
                UserPoolId=pool_id,
                CloudWatchLogsRoleArn=role_arn,
            )
        )
    )
    assert repeat_code == "LimitExceededException", (
        f"expected the quota boundary to stay durable on a second attempt, got {repeat_code}"
    )
    expected_repeat_message = "The limit for user pool import jobs is: 1000."
    assert repeat_message == expected_repeat_message, (
        f"expected message {expected_repeat_message!r}, got {repeat_message!r}"
    )

    # Terminal independent read at the destination: the rejected job must not
    # merely have been rejected in its own response -- it must not exist.
    # Walk ListUserImportJobs (bounded, not a hardcoded quota assumption) looking
    # for the exact JobName the rejected call used.
    list_kwargs = {"UserPoolId": pool_id, "MaxResults": 60}
    found_rejected_job = False
    for _ in range(40):
        page = _retry_throttled(lambda: c.list_user_import_jobs(**list_kwargs))
        if any(job["JobName"] == over_again_name for job in page["UserImportJobs"]):
            found_rejected_job = True
            break
        token = page.get("PaginationToken")
        if not token:
            break
        list_kwargs["PaginationToken"] = token
    assert not found_rejected_job, (
        f"CreateUserImportJob for JobName={over_again_name!r} returned "
        "LimitExceededException, but ListUserImportJobs shows it exists anyway"
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
