"""start-policy-generation-completes-then-cancel-terminal-rejected."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-policy-generation-completes-then-cancel-terminal-rejected"
GROUP = "error-semantics"
SERVICES = ["accessanalyzer"]
_CLEANUP_S = 300.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartPolicyGeneration rejects a missing or unknown trail with ValidationException and
    mints a job for a real trail; cancelling that job once it SUCCEEDED is rejected, re-cancelling
    a CANCELED job is accepted, and a never-issued jobId is rejected as not existing."""
    iam = ctx.client("iam")
    aa = ctx.client("accessanalyzer")
    sts = ctx.client("sts")
    ct = ctx.client("cloudtrail")
    s3 = ctx.client("s3")

    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-aa-policygen-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "access-analyzer.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    readonly_policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=readonly_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=readonly_policy_arn))

    # (1) cloudTrailDetails omitted entirely -> rejected before any job is created.
    code, msg = _error_code_and_message(
        lambda: aa.start_policy_generation(policyGenerationDetails={"principalArn": role_arn})
    )
    assert code == "ValidationException", f"expected ValidationException for missing cloudTrailDetails, got {code}"
    assert msg == "Missing cloudTrailDetails", msg

    # (2) cloudTrailDetails referencing a trail that doesn't exist -> also rejected
    # synchronously (AWS validates the trail via cloudtrail:GetTrail before minting a job).
    now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    fake_trail_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:trail/{role_name}-notrail"
    # A just-created role is not yet assumable, and until it is the call reports the access role
    # instead of the trail; the bounded loop waits out that IAM propagation window.
    deadline = time.monotonic() + 90
    while True:
        code2, msg2 = _error_code_and_message(
            lambda: aa.start_policy_generation(
                policyGenerationDetails={"principalArn": role_arn},
                cloudTrailDetails={
                    "accessRole": role_arn,
                    "startTime": now - datetime.timedelta(days=1),
                    "endTime": now,
                    "trails": [{"cloudTrailArn": fake_trail_arn, "allRegions": True}],
                },
            )
        )
        if msg2 != "Invalid accessRole: Unauthorized to perform sts:AssumeRole" or time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    assert code2 == "ValidationException", f"expected ValidationException for a nonexistent trail, got {code2}"
    assert msg2 == (
        f"Invalid cloudTrailArn: {fake_trail_arn}. Unknown trail: {role_name}-notrail for the user: {account_id}"
    ), msg2

    # Positive control: a REAL trail this check provisions makes the identical call succeed,
    # proving (2)'s rejection is specifically about trail existence and not a blanket refusal.
    bucket = ctx.unique_name("sim2real-aa-policygen-bkt-").lower()
    _create_trail_bucket(s3, bucket, ctx.region, account_id)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    trail_name = ctx.unique_name("sim2real-aa-policygen-trail-")
    real_trail_arn = _retry_cloudtrail(
        lambda: ct.create_trail(
            Name=trail_name,
            S3BucketName=bucket,
            TagsList=[{"Key": "sim2real", "Value": CHECK}],
        )
    )["TrailARN"]
    ctx.on_cleanup(lambda: _delete_trail(ct, trail_name))

    def _start_real():
        return aa.start_policy_generation(
            policyGenerationDetails={"principalArn": role_arn},
            cloudTrailDetails={
                "accessRole": role_arn,
                "startTime": now - datetime.timedelta(days=1),
                "endTime": now,
                "trails": [{"cloudTrailArn": real_trail_arn, "allRegions": True}],
            },
        )

    # IAM role/policy attachment is eventually consistent; StartPolicyGeneration's own
    # downstream role check can 403 for a few seconds after attach_role_policy returns.
    start_resp = _retry_role_propagation(_start_real)
    job_id = start_resp["jobId"]
    assert job_id, f"expected a jobId from a real trail, got {start_resp!r}"

    def _read_status():
        return aa.get_generated_policy(jobId=job_id)["jobDetails"]["status"]

    def _poll_natural_terminal():
        status = _read_status()
        if status == "IN_PROGRESS":
            raise _NotYetTerminal(status)
        return status

    # A new trail with no activity for the role normally completes on its own with an empty
    # policy; if it is still running at the budget it is cancelled below. Either terminal state
    # is read back through GetGeneratedPolicy, not the mutating call's response.
    try:
        natural_status = _poll_until(_poll_natural_terminal, timeout_s=60, interval_s=3.0)
    except AssertionError:
        natural_status = "IN_PROGRESS"

    if natural_status != "IN_PROGRESS":
        # The job reached an outcome on its own: cancelling it is an illegal status change
        # (ValidationException), unlike re-cancelling a job the caller already cancelled.
        cancel_code, cancel_msg = _error_code_and_message(lambda: aa.cancel_policy_generation(jobId=job_id))
        assert cancel_code == "ValidationException", (
            f"expected ValidationException canceling an already-{natural_status} job, got {cancel_code}"
        )
        assert cancel_msg == (
            f"Invalid jobId: {job_id}. Illegal status change from {natural_status} to CANCELED"
        ), cancel_msg
        poststatus = _read_status()
        assert poststatus == natural_status, (
            f"expected the rejected cancel to leave status unchanged, got {poststatus}"
        )
    else:
        # Still running at the budget: cancel it ourselves and prove -- via an
        # INDEPENDENT read -- that it lands in the terminal CANCELED state.
        aa.cancel_policy_generation(jobId=job_id)
        terminal_status = _poll_until(_poll_natural_terminal, timeout_s=60, interval_s=2.0)
        assert terminal_status == "CANCELED", (
            f"expected the canceled job to read back CANCELED, got {terminal_status}"
        )
        # Re-cancelling an already-CANCELED job is accepted as a no-op; only a jobId that
        # never existed is rejected (exercised below).
        aa.cancel_policy_generation(jobId=job_id)
        restatus = _read_status()
        assert restatus == "CANCELED", f"expected the accepted re-cancel to leave status CANCELED, got {restatus}"

    # (3) A well-formed but never-issued jobId is rejected with ValidationException: neither
    # CancelPolicyGeneration nor GetGeneratedPolicy documents a ResourceNotFoundException.
    fake_job_id = "00000000-0000-0000-0000-000000000000"
    cancel_code, fake_cancel_msg = _error_code_and_message(lambda: aa.cancel_policy_generation(jobId=fake_job_id))
    assert cancel_code == "ValidationException", (
        f"expected ValidationException canceling a never-issued jobId, got {cancel_code}"
    )
    assert fake_cancel_msg == f"Invalid jobId: {fake_job_id} does not exist", fake_cancel_msg
    get_code, fake_get_msg = _error_code_and_message(lambda: aa.get_generated_policy(jobId=fake_job_id))
    assert get_code == "ValidationException", (
        f"expected ValidationException getting a never-issued jobId, got {get_code}"
    )
    assert fake_get_msg == f"Invalid jobId: {fake_job_id} does not exist", fake_get_msg


class _NotYetTerminal(Exception):
    pass


def _poll_until(fn, timeout_s, interval_s):
    """Bounded retry with a stated reason: waits for a real async job to leave IN_PROGRESS."""
    deadline = time.monotonic() + timeout_s
    last_status = None
    while True:
        try:
            return fn()
        except _NotYetTerminal as exc:
            last_status = exc.args[0]
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"job did not reach a terminal state within {timeout_s}s, last status {last_status!r}"
                ) from None
            time.sleep(interval_s)


def _error_code_and_message(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises, so a target
    accepting what AWS refuses cannot be read as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _retry_cloudtrail(fn, attempts=6):
    """Retry transient CloudTrail control-plane errors (bucket policy propagation, throttling)."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("InsufficientS3BucketPolicyException", "ThrottlingException") and i < attempts - 1:
                last = exc
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise last


def _retry_role_propagation(fn, attempts=6):
    """Retry the specific window where a just-attached IAM policy hasn't propagated yet."""
    last = None
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("AccessDeniedException", "ValidationException") and i < attempts - 1:
                last = exc
                time.sleep(2.0 * (i + 1))
                continue
            raise
    raise last


def _create_trail_bucket(s3, bucket, region, account_id):
    """Create an S3 bucket with the policy CloudTrail needs to deliver logs.

    "us-east-1" below is not a region pin -- S3's CreateBucket rejects an explicit
    LocationConstraint for that region specifically, so this is a comparison against
    that one documented exception, not a hardcoded target region.
    """
    kwargs = {"Bucket": bucket}
    if region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in ("BucketAlreadyOwnedByYou", "BucketAlreadyExists"):
            raise
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "policygen-check"}]})
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSCloudTrailAclCheck",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
            },
            {
                "Sid": "AWSCloudTrailWrite",
                "Effect": "Allow",
                "Principal": {"Service": "cloudtrail.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": [
                    f"arn:aws:s3:::{bucket}/AWSLogs/{account_id}/*",
                    f"arn:aws:s3:::{bucket}/*/AWSLogs/{account_id}/*",
                ],
                "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket, Policy=json.dumps(policy))


def _empty_and_delete_bucket(s3, bucket):
    # CloudTrail can deliver a log object after its trail is gone, so a BucketNotEmpty answer
    # re-empties the bucket and retries every 2 s to the cleanup deadline.
    deadline = time.monotonic() + _CLEANUP_S
    while True:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                objs = page.get("Contents", [])
                if objs:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty" or time.monotonic() >= deadline:
                raise
        time.sleep(2.0)


def _delete_trail(ct, name):
    try:
        ct.stop_logging(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise
    try:
        _retry_cloudtrail(lambda: ct.delete_trail(Name=name))
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TrailNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
