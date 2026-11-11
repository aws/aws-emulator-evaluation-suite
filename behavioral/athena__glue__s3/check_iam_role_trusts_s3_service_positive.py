"""iam-role-trusts-s3-service-positive."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "iam-role-trusts-s3-service-positive"
GROUP = "iam-trust"
SERVICES = ["athena", "glue", "s3"]

# S3 Batch Operations assumes roles as batchoperations.s3.amazonaws.com, not s3.amazonaws.com.
# https://docs.aws.amazon.com/AmazonS3/latest/userguide/batch-ops-iam-role-policies.html
_S3_BATCH_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "batchoperations.s3.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A role trusting batchoperations.s3.amazonaws.com is assumable by S3 Batch Operations: a
    PutObjectTagging job using it reaches Complete and the tag lands on the object.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/batch-ops-iam-role-policies.html
    """
    sts = ctx.client("sts")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    s3control = ctx.client("s3control")
    account_id = sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-s3trust-")
    _create_bucket(ctx, s3, bucket)
    key = "objects/target.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"hello-batch")

    manifest_key = "manifest/manifest.csv"
    manifest_body = f"{bucket},{key}\n".encode()
    put_resp = s3.put_object(Bucket=bucket, Key=manifest_key, Body=manifest_body)
    etag = put_resp["ETag"]

    role_name = ctx.unique_name("sim2real-s3trust-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_S3_BATCH_TRUST),
        Tags=[{"Key": "sim2real", "Value": "iam-role-trusts-s3-service-positive"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": f"arn:aws:s3:::{bucket}/{manifest_key}"},
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:PutObjectTagging"],
                "Resource": f"arn:aws:s3:::{bucket}/*",
            },
            {"Effect": "Allow", "Action": ["s3:GetBucketLocation"], "Resource": f"arn:aws:s3:::{bucket}"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="batch-ops", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="batch-ops"))

    manifest_arn = f"arn:aws:s3:::{bucket}/{manifest_key}"
    report_bucket_arn = f"arn:aws:s3:::{bucket}"

    def _create_and_run_job() -> str:
        job_id = s3control.create_job(
            AccountId=account_id,
            ConfirmationRequired=False,
            Operation={"S3PutObjectTagging": {"TagSet": [{"Key": "batch", "Value": "true"}]}},
            Manifest={
                "Spec": {"Format": "S3BatchOperations_CSV_20180820", "Fields": ["Bucket", "Key"]},
                "Location": {"ObjectArn": manifest_arn, "ETag": etag},
            },
            Report={
                "Bucket": report_bucket_arn,
                "Prefix": "reports",
                "Format": "Report_CSV_20180820",
                "Enabled": True,
                "ReportScope": "AllTasks",
            },
            Priority=1,
            RoleArn=role_arn,
        )["JobId"]
        ctx.on_cleanup(lambda: _try_cancel_job(s3control, account_id, job_id))
        return job_id

    final_status = None
    for _attempt in range(2):
        job_id = _create_and_run_job()
        final_status = _wait_for_job_terminal(s3control, account_id, job_id, timeout_s=280)
        if final_status == "Complete":
            break
        # A freshly created IAM role can take a short time to become assumable by
        # another AWS service (documented eventual consistency); retry once.
        time.sleep(2)

    assert final_status == "Complete", f"S3 Batch Operations job never completed (last status={final_status!r})"

    tagging = s3.get_object_tagging(Bucket=bucket, Key=key)
    tags = {t["Key"]: t["Value"] for t in tagging["TagSet"]}
    assert tags.get("batch") == "true", f"batch job completed but tag was not applied: {tags}"


def _create_bucket(ctx, s3, name: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "iam-role-trusts-s3-service-positive"},
    ]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, name))


def _empty_and_delete_bucket(s3, name: str) -> None:
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=name):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=name)


def _wait_for_job_terminal(s3control, account_id: str, job_id: str, timeout_s: int = 280) -> str | None:
    terminal = {"Complete", "Failed", "Cancelled"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = s3control.describe_job(AccountId=account_id, JobId=job_id)["Job"]["Status"]
        if status in terminal:
            return status
        time.sleep(2)
    return status


def _try_cancel_job(s3control, account_id: str, job_id: str) -> None:
    """Cancel the job unless it already ended or is ending; a missing job is clean, anything else raises.
    A job in a state that cannot be cancelled yet answers JobStatusException, retried for 60 s."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60.0
    while True:
        try:
            status = s3control.describe_job(AccountId=account_id, JobId=job_id)["Job"]["Status"]
            if status in ("Complete", "Completing", "Failed", "Failing", "Cancelled", "Cancelling"):
                return
            s3control.update_job_status(AccountId=account_id, JobId=job_id, RequestedJobStatus="Cancelled")
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "JobStatusException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
