"""batch-job-tagging-lifecycle-independent-of-job."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-job-tagging-lifecycle-independent-of-job"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("cap:c1", "concern:representation", "plane:control", "axis:happy-path")
def run(ctx) -> None:
    """CreateJob tags read back, PutJobTagging replaces them wholesale, and DeleteJobTagging leaves
    a 200 empty list rather than a 404, without perturbing the job's description or status."""
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-jtag-")
    role = ctx.unique_name("sim2real-behav-jtagrole-")

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="obj/a.txt", Body=b"tag-target")
    manifest_etag = s3.put_object(
        Bucket=bucket, Key="manifest.csv", Body=f"{bucket},obj/a.txt\n".encode()
    )["ETag"].strip('"')
    role_arn = _batch_role(ctx, iam, role, bucket)

    job_id = None
    deadline = _deadline(ctx, 100)
    while True:
        try:
            job_id = s3c.create_job(
                AccountId=account,
                ConfirmationRequired=True,
                Operation={
                    "S3PutObjectTagging": {"TagSet": [{"Key": "op", "Value": "tag"}]}
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
                Priority=5,
                RoleArn=role_arn,
                Description="sim2real-behav job tagging",
                Tags=[{"Key": "sim2real", "Value": "job"}, {"Key": "phase", "Value": "one"}],
            )["JobId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BadRequestException":
                raise
            if time.monotonic() >= deadline:
                break
            time.sleep(2)
    assert job_id, "CreateJob never succeeded — the batch role did not become usable"
    ctx.on_cleanup(lambda: _cancel_job(s3c, account, job_id))

    at_create = {
        t["Key"]: t["Value"]
        for t in s3c.get_job_tagging(AccountId=account, JobId=job_id)["Tags"]
    }
    assert at_create == {"sim2real": "job", "phase": "one"}, (
        f"the tags supplied at CreateJob read back as {at_create!r}"
    )

    # A ConfirmationRequired job prepares on its own and settles (Suspended, awaiting
    # confirmation); the baseline is that settled state, so only the tag churn could move it.
    before = _settled_job(ctx, s3c, account, job_id)
    baseline_status, baseline_priority = before["Status"], before["Priority"]

    s3c.put_job_tagging(
        AccountId=account, JobId=job_id,
        Tags=[{"Key": "sim2real", "Value": "job"}, {"Key": "phase", "Value": "two"}],
    )
    replaced = {
        t["Key"]: t["Value"]
        for t in s3c.get_job_tagging(AccountId=account, JobId=job_id)["Tags"]
    }
    assert replaced == {"sim2real": "job", "phase": "two"}, (
        f"PutJobTagging left {replaced!r}; it must REPLACE the set, not merge phase=one back in"
    )

    s3c.delete_job_tagging(AccountId=account, JobId=job_id)
    emptied = s3c.get_job_tagging(AccountId=account, JobId=job_id)["Tags"]
    assert emptied == [], (
        f"GetJobTagging after DeleteJobTagging returned {emptied!r}, expected an empty list"
    )

    after = s3c.describe_job(AccountId=account, JobId=job_id)["Job"]
    assert (after["Status"], after["Priority"]) == (baseline_status, baseline_priority), (
        f"the tag churn moved the job: status/priority were "
        f"{(baseline_status, baseline_priority)!r}, now {(after['Status'], after['Priority'])!r}"
    )
    assert after["Description"] == "sim2real-behav job tagging", (
        f"the job description changed to {after['Description']!r}"
    )


# ===== helpers =====

_SETTLED_JOB = ("Suspended", "Failed", "Cancelled", "Complete")


def _settled_job(ctx, s3c, account: str, job_id: str) -> dict:
    """DescribeJob's Job once its status leaves the New/Preparing transition."""
    deadline = _deadline(ctx, 180)
    while True:
        job = s3c.describe_job(AccountId=account, JobId=job_id)["Job"]
        if job["Status"] in _SETTLED_JOB:
            return job
        if time.monotonic() >= deadline:
            left = ctx.time_left()
            if left is not None and left <= 6.0:
                raise TimeoutError("job settling: the run budget ended first; not graded")
            raise AssertionError(f"job {job_id} never settled past {job['Status']!r}")
        time.sleep(2)


def _deadline(ctx, seconds: float) -> float:
    """A monotonic deadline ``seconds`` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else max(1.0, min(seconds, left - 5.0)))


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
    # IAM propagation exposes no condition to poll; the CreateJob retry loop in run()
    # is the bounded wait — it retries on BadRequestException (role not yet assumable).
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
