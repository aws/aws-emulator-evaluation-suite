"""iam-role-trust-s3-service-assumed-for-batch-op-positive."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iam-role-trust-s3-service-assumed-for-batch-op-positive"
GROUP = "iam-trust"
SERVICES = ["emr", "glue", "s3"]

_TERMINAL_STATUSES = {"Complete", "Failed", "Cancelled"}
_TAG = {"Key": "sim2real", "Value": "tagged"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """An IAM role trusting batchoperations.s3.amazonaws.com is assumed by a real S3 Batch
    Operations job, which then successfully tags the target object -- proving the role was
    actually used to perform the batch action, not merely accepted at CreateJob time."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    s3control = ctx.client("s3control")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = _create_bucket(ctx, s3)
    target_key = "data/target.txt"
    manifest_key = "manifest.csv"
    s3.put_object(Bucket=bucket, Key=target_key, Body=b"hello")
    before_tags = s3.get_object_tagging(Bucket=bucket, Key=target_key)["TagSet"]
    assert before_tags == [], f"target object already carried tags before the job ran: {before_tags!r}"
    manifest_body = f"{bucket},{target_key}\n"
    etag = s3.put_object(Bucket=bucket, Key=manifest_key, Body=manifest_body.encode())["ETag"]

    perms = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:PutObject"], "Resource": f"arn:aws:s3:::{bucket}/reports/*"},
            {"Effect": "Allow", "Action": ["s3:PutObjectTagging"], "Resource": f"arn:aws:s3:::{bucket}/*"},
        ],
    }
    role_arn = _create_role(
        ctx, iam, ctx.unique_name("sim2real-batchops-trust-"),
        {"Service": "batchoperations.s3.amazonaws.com"},
        inline_policies={"batchops-perms": perms},
    )

    final = _run_job_until_role_assumed(ctx, s3control, account_id, bucket, manifest_key, etag, role_arn)
    assert final["Status"] == "Complete", f"unexpected job status: {final}"

    after_tags = s3.get_object_tagging(Bucket=bucket, Key=target_key)["TagSet"]
    assert after_tags == [_TAG], f"expected exactly the job's tag {_TAG!r}, got {after_tags!r}"


def _try_cancel(s3control, account_id: str, job_id: str) -> None:
    try:
        s3control.update_job_status(AccountId=account_id, JobId=job_id, RequestedJobStatus="Cancelled")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _run_job_until_role_assumed(
    ctx,
    s3control,
    account_id: str,
    bucket: str,
    manifest_key: str,
    etag: str,
    role_arn: str,
    deadline_s: float = 200,
    retry_interval_s: float = 10,
) -> dict:
    """S3 Batch Operations does not validate role assumability when CreateJob is called -- it
    assumes the role asynchronously once the job actually starts running, moments later. A role
    created moments ago can therefore terminate Failed with the specific 'Could not assume the
    IAM role' AccessDenied purely from IAM propagation lag, even though the trust policy is
    already correct. A Failed job cannot be resubmitted, so retry with a brand-new job until the
    role is actually assumed or the deadline passes -- that observable is what the deadline
    waits for, never a fixed guess at the propagation time."""
    deadline = time.monotonic() + deadline_s
    last: dict = {}
    while True:
        job_id = _create_job(s3control, account_id, bucket, manifest_key, etag, role_arn, ctx.unique_name("token-"))
        ctx.on_cleanup(lambda jid=job_id: _try_cancel(s3control, account_id, jid))
        last = _poll_until(
            lambda: s3control.describe_job(AccountId=account_id, JobId=job_id)["Job"],
            lambda j: j["Status"] in _TERMINAL_STATUSES,
            timeout_s=90,
            interval_s=5,
        )
        if last["Status"] == "Complete":
            return last
        reasons = last.get("FailureReasons") or []
        role_not_yet_assumable = any(
            "Could not assume the IAM role" in r.get("FailureReason", "") for r in reasons
        )
        if not role_not_yet_assumable or time.monotonic() >= deadline:
            return last
        time.sleep(retry_interval_s)


def _create_job(s3control, account_id: str, bucket: str, manifest_key: str, etag: str, role_arn: str, token: str) -> str:
    return s3control.create_job(
        AccountId=account_id,
        ConfirmationRequired=False,
        Operation={"S3PutObjectTagging": {"TagSet": [_TAG]}},
        Report={
            "Bucket": f"arn:aws:s3:::{bucket}",
            "Prefix": "reports",
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
        Description="sim2real-behav-positive",
        ClientRequestToken=token,
    )["JobId"]


def _create_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-s3-batchops-")
    if ctx.region == "us-east-1":
        # us-east-1 is the one region CreateBucket rejects a LocationConstraint for.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "batchops-trust"}]})
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
    managed_policy_arns: list[str] | None = None,
    inline_policies: dict[str, dict] | None = None,
) -> str:
    trust_doc = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": trust_principal, "Action": "sts:AssumeRole"}]}
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_doc,
        Tags=[{"Key": "sim2real", "Value": "batchops-trust"}],
    )["Role"]["Arn"]

    def _cleanup() -> None:
        for arn in managed_policy_arns or []:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
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
    for arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
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
