"""batch-job-runs-to-completion-and-tags-objects."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-job-runs-to-completion-and-tags-objects"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("cap:c3", "concern:data-plane", "dp:api", "plane:data", "axis:happy-path")
def run(ctx) -> None:
    """A no-confirmation S3PutObjectTagging job runs to Complete on its own, the manifest's object
    ends up carrying exactly the job's tag set, and ProgressSummary reports one task succeeded.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-jrun-")
    role = ctx.unique_name("sim2real-behav-jrunrole-")

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="obj/a.txt", Body=b"to-be-tagged")
    assert s3.get_object_tagging(Bucket=bucket, Key="obj/a.txt")["TagSet"] == [], (
        "the target object already carried tags before the job ran"
    )
    manifest_etag = s3.put_object(
        Bucket=bucket, Key="manifest.csv", Body=f"{bucket},obj/a.txt\n".encode()
    )["ETag"].strip('"')
    role_arn = _batch_role(ctx, iam, role, bucket)

    # IAM propagation exposes no condition to poll: CreateJob's own validation of the role
    # catches an unusable trust/permission policy synchronously (retried below), but a job
    # can still start and have the batch operations service fail to assume the role because
    # propagation finished a few seconds later. Bound that with a second retry layer, over the
    # job's own terminal outcome rather than a fixed sleep: at least 6 jobs, and retries to 600 s.
    job = None
    outer = _deadline(ctx, 600)
    job_attempts = 0
    while True:
        job_attempts += 1
        job_id = None
        deadline = _deadline(ctx, 100)
        while True:
            try:
                job_id = s3c.create_job(
                    AccountId=account,
                    ConfirmationRequired=False,
                    Operation={
                        "S3PutObjectTagging": {
                            "TagSet": [{"Key": "sim2real", "Value": "batchran"}]
                        }
                    },
                    Report={
                        "Bucket": f"arn:aws:s3:::{bucket}",
                        "Format": "Report_CSV_20180820",
                        "Enabled": True,
                        "Prefix": "reports",
                        "ReportScope": "AllTasks",
                    },
                    Manifest={
                        "Spec": {
                            "Format": "S3BatchOperations_CSV_20180820",
                            "Fields": ["Bucket", "Key"],
                        },
                        "Location": {
                            "ObjectArn": f"arn:aws:s3:::{bucket}/manifest.csv",
                            "ETag": manifest_etag,
                        },
                    },
                    Priority=10,
                    RoleArn=role_arn,
                    Description="sim2real-behav batch execution",
                    Tags=[{"Key": "sim2real", "Value": "batchrun"}],
                )["JobId"]
                break
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "BadRequestException":
                    raise
                if time.monotonic() >= deadline:
                    break
                time.sleep(2)
        assert job_id, "CreateJob never succeeded — the batch role did not become usable"
        ctx.on_cleanup(lambda jid=job_id: _cancel_job(s3c, account, jid))

        job = _poll_terminal(s3c, account, job_id)
        reasons = job.get("FailureReasons") or []
        role_not_yet_assumable = job["Status"] == "Failed" and any(
            r.get("FailureCode") == "AccessDenied"
            and "assume the IAM role" in r.get("FailureReason", "")
            for r in reasons
        )
        if not role_not_yet_assumable or (job_attempts >= 6 and time.monotonic() >= outer):
            break
        time.sleep(2)
    assert job["Status"] == "Complete", (
        f"the job settled into {job['Status']!r} (reasons {job.get('FailureReasons')!r}), "
        "expected Complete"
    )
    summary = job.get("ProgressSummary", {})
    assert summary.get("TotalNumberOfTasks") == 1, (
        f"ProgressSummary reported {summary!r}, expected exactly one task"
    )
    assert summary.get("NumberOfTasksSucceeded") == 1 and summary.get(
        "NumberOfTasksFailed"
    ) == 0, f"ProgressSummary reported {summary!r}, expected one succeeded and zero failed"

    tag_set = {
        t["Key"]: t["Value"]
        for t in s3.get_object_tagging(Bucket=bucket, Key="obj/a.txt")["TagSet"]
    }
    assert tag_set == {"sim2real": "batchran"}, (
        f"after the job the object carried tags {tag_set!r}, expected the job's single tag"
    )


# ===== helpers =====

def _deadline(ctx, seconds: float) -> float:
    """A monotonic deadline ``seconds`` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else max(1.0, min(seconds, left - 5.0)))


def _poll_terminal(s3c, account: str, job_id: str, attempts: int = 90) -> dict:
    job = None
    for _ in range(attempts):
        job = s3c.describe_job(AccountId=account, JobId=job_id)["Job"]
        if job["Status"] in ("Complete", "Failed", "Cancelled"):
            return job
        time.sleep(3)
    raise TimeoutError(
        f"job {job_id} did not reach a terminal state within {attempts * 3}s; "
        f"last observed status {job['Status'] if job else None!r}"
    )


def _cancel_job(s3c, account: str, job_id: str) -> None:
    try:
        status = s3c.describe_job(AccountId=account, JobId=job_id)["Job"]["Status"]
        if status in ("New", "Preparing", "Suspended", "Ready", "Active", "Paused"):
            s3c.update_job_status(
                AccountId=account, JobId=job_id, RequestedJobStatus="Cancelled",
                StatusUpdateReason="sim2real behav teardown",
            )
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] == "InvalidRequest" and err.get("Message") == "Job not found":
            return
        # A job that turned terminal between the read and the cancel needs nothing more.
        if err["Code"] != "InvalidRequest" or s3c.describe_job(AccountId=account, JobId=job_id)[
            "Job"
        ]["Status"] not in ("Complete", "Completing", "Failed", "Failing", "Cancelled", "Cancelling"):
            raise


def _batch_role(ctx, iam, role: str, bucket: str) -> str:
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "batchoperations.s3.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role, AssumeRolePolicyDocument=json.dumps(trust)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role))
    iam.put_role_policy(
        RoleName=role, PolicyName="batch",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject", "s3:PutObjectTagging", "s3:GetObjectTagging",
                        "s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket",
                    ],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        }),
    )
    # IAM propagation exposes no condition to poll; the CreateJob retry loop above, which
    # retries on BadRequestException for up to 100s, is the bounded wait for it.
    return role_arn


def _delete_role(iam, role: str) -> None:
    try:
        for name in iam.list_role_policies(RoleName=role).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role, PolicyName=name)
        iam.delete_role(RoleName=role)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_bucket(ctx, s3, name: str) -> None:
    params: dict = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)


def _empty_and_delete_bucket(s3, name: str) -> None:
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=name):
            objs = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                s3.delete_objects(Bucket=name, Delete={"Objects": objs})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
        return
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
