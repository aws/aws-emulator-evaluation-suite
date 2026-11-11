"""s3-batch-operation-role-missing-s3-trust-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-batch-operation-role-missing-s3-trust-rejected"
GROUP = "permission-boundary"
SERVICES = ["emr", "glue", "s3"]

_TERMINAL_STATUSES = {"Complete", "Failed", "Cancelled"}


@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An S3 Batch Operations job whose role trusts ec2.amazonaws.com ends Failed and tags nothing.

    An identical job whose role trusts batchoperations.s3.amazonaws.com completes and tags its
    target, isolating the failure to the trust principal."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    s3control = ctx.client("s3control")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = _create_bucket(ctx, s3)
    perms = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket}/reports/*"},
            {"Effect": "Allow", "Action": ["s3:PutObjectTagging"], "Resource": f"arn:aws:s3:::{bucket}/*"},
        ],
    }
    good_role_arn = _create_role(
        ctx, iam, ctx.unique_name("sim2real-batchgoodtrust-"),
        {"Service": "batchoperations.s3.amazonaws.com"},
        inline_policies={"perms": perms},
    )
    bad_role_arn = _create_role(
        ctx, iam, ctx.unique_name("sim2real-batchbadtrust-"),
        {"Service": "ec2.amazonaws.com"},  # only the trust principal differs from the good role
        inline_policies={"perms": perms},
    )

    good_final, good_target_key = _run_job_until_settled(ctx, s3, s3control, account_id, bucket, good_role_arn, "good")
    bad_final, bad_target_key = _run_job_until_settled(ctx, s3, s3control, account_id, bucket, bad_role_arn, "bad")

    # Positive control: the correctly-trusted role's job completes and tags its target.
    assert good_final["Status"] == "Complete", f"positive control failed: {good_final}"
    good_tags = s3.get_object_tagging(Bucket=bucket, Key=good_target_key)["TagSet"]
    assert {"Key": "sim2real", "Value": "tagged"} in good_tags, f"expected sim2real=tagged, got {good_tags}"

    # Negative: the mistrusted role's job fails, and its target is never tagged.
    assert bad_final["Status"] == "Failed", f"expected Failed, got: {bad_final}"
    assert bad_final.get("FailureReasons"), "Failed job should carry FailureReasons"
    bad_tags = s3.get_object_tagging(Bucket=bucket, Key=bad_target_key)["TagSet"]
    assert {"Key": "sim2real", "Value": "tagged"} not in bad_tags, f"expected no sim2real tag, got {bad_tags}"


# ===== helpers =====

def _run_job_until_settled(
    ctx, s3, s3control, account_id: str, bucket: str, role_arn: str, label: str,
    max_attempts: int = 6, retry_wait_s: float = 10,
) -> tuple[dict, str]:
    """Submit-and-poll, bounded-retrying a settle into Failed with the specific
    "could not assume the IAM role" reason: real AWS attempts the role assumption
    asynchronously when the job starts running, which lands inside the same IAM
    propagation window as CreateJob itself, so even a correctly-trusted role can settle
    Failed once before it settles Complete. A permanently-mistrusted role keeps failing
    the same way on every attempt and exhausts the budget still Failed, which is the
    correct terminal answer for it."""
    final, target_key = None, None
    for attempt in range(max_attempts):
        submitted = _submit_job(ctx, s3, s3control, account_id, bucket, role_arn, label)
        target_key = submitted["target_key"]
        final = _poll_until(
            lambda: s3control.describe_job(AccountId=account_id, JobId=submitted["job_id"])["Job"],
            lambda j: j["Status"] in _TERMINAL_STATUSES,
            timeout_s=120,
            interval_s=5,
        )
        if final["Status"] != "Failed" or not _is_assume_role_propagation_failure(final):
            return final, target_key
        if attempt < max_attempts - 1:
            time.sleep(retry_wait_s)
    return final, target_key


def _is_assume_role_propagation_failure(job: dict) -> bool:
    return any(
        "Could not assume the IAM role" in r.get("FailureReason", "")
        for r in job.get("FailureReasons") or []
    )


def _submit_job(ctx, s3, s3control, account_id: str, bucket: str, role_arn: str, label: str) -> dict[str, str]:
    target_key = f"data/{label}.txt"
    manifest_key = f"manifest-{label}.csv"
    s3.put_object(Bucket=bucket, Key=target_key, Body=b"hello")
    etag = s3.put_object(Bucket=bucket, Key=manifest_key, Body=f"{bucket},{target_key}\n".encode())["ETag"]

    # IAM role/policy propagation is eventually consistent: CreateJob can reject a just-created
    # role with BadRequestException until the trust document has propagated. Retry that specific
    # error, bounded, instead of guessing a fixed delay.
    job_id = None
    deadline = time.monotonic() + 100.0
    if ctx.time_left() is not None:
        deadline = min(deadline, time.monotonic() + ctx.time_left())
    while time.monotonic() < deadline:
        try:
            job_id = s3control.create_job(
                AccountId=account_id,
                ConfirmationRequired=False,
                Operation={"S3PutObjectTagging": {"TagSet": [{"Key": "sim2real", "Value": "tagged"}]}},
                Report={
                    "Bucket": f"arn:aws:s3:::{bucket}",
                    "Prefix": f"reports/{label}",
                    "Format": "Report_CSV_20180820",
                    "Enabled": True,
                    "ReportScope": "AllTasks",
                },
                Manifest={
                    "Spec": {"Format": "S3BatchOperations_CSV_20180820", "Fields": ["Bucket", "Key"]},
                    "Location": {"ObjectArn": f"arn:aws:s3:::{bucket}/{manifest_key}", "ETag": etag},
                },
                Priority=1,
                RoleArn=role_arn,
                Description=f"sim2real-behav-negative-{label}",
                ClientRequestToken=ctx.unique_name(f"token-{label}-"),
            )["JobId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BadRequestException":
                raise
            time.sleep(2)
    assert job_id, f"CreateJob for the {label} role never succeeded — the role never became usable"
    ctx.on_cleanup(lambda: _try_cancel(s3control, account_id, job_id))
    return {"job_id": job_id, "target_key": target_key}


def _try_cancel(s3control, account_id: str, job_id: str) -> None:
    # A job in a terminal status refuses any status update ("Requested job status forbidden").
    try:
        if s3control.describe_job(AccountId=account_id, JobId=job_id)["Job"]["Status"] in _TERMINAL_STATUSES:
            return
        s3control.update_job_status(AccountId=account_id, JobId=job_id, RequestedJobStatus="Cancelled")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-s3-batchops-neg-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    resp = s3.list_objects_v2(Bucket=bucket)
    objs = resp.get("Contents", [])
    if objs:
        failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _create_role(
    ctx,
    iam,
    role_name: str,
    trust_principal: dict[str, Any],
    inline_policies: dict[str, dict] | None = None,
) -> str:
    trust_doc = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": trust_principal, "Action": "sts:AssumeRole"}]}
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_doc)["Role"]["Arn"]

    def _cleanup() -> None:
        for pname in (inline_policies or {}):
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    for pname, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=role_name, PolicyName=pname, PolicyDocument=json.dumps(doc))
    return role_arn


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
