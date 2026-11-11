"""batch-job-lifecycle-priority-and-cancel."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-job-lifecycle-priority-and-cancel"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags(
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
    "axis:happy-path",
)
def run(ctx) -> None:
    """A ConfirmationRequired Batch Operations job settles into Suspended, UpdateJobPriority
    is reflected by DescribeJob and ListJobs, and UpdateJobStatus(Cancelled) drives it to a
    terminal Cancelled state from which a resume to Ready is refused with InvalidRequest.
    """
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-jobb-")
    role = ctx.unique_name("sim2real-behav-jobrole-")

    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="obj/a.txt", Body=b"batch-target")
    manifest_etag = s3.put_object(
        Bucket=bucket, Key="manifest.csv", Body=f"{bucket},obj/a.txt\n".encode()
    )["ETag"].strip('"')

    role_arn = _batch_role(ctx, iam, role, bucket)

    # IAM role propagation: CreateJob validates the trust/permission of the role, which is not
    # visible immediately after creation. Retry CreateJob on that transient rejection.
    job_id = None
    status = None
    for _job_attempt in range(5):
        job_id = None
        deadline = _deadline(ctx, 100)
        while True:
            try:
                job_id = s3c.create_job(
                    AccountId=account,
                    ConfirmationRequired=True,
                    Operation={
                        "S3PutObjectTagging": {"TagSet": [{"Key": "sim2real", "Value": "batch"}]}
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
                    Description="sim2real-behav batch lifecycle",
                    Tags=[{"Key": "sim2real", "Value": "job"}],
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

        # A ConfirmationRequired job settles into Suspended, awaiting confirmation, rather than
        # running on its own.
        status = _poll_job_status(s3c, account, job_id, {"Suspended", "Failed", "Cancelled"})
        if status == "Suspended":
            break
        # A Failed settlement this early is the role's inline permission policy not yet visible
        # to S3 Batch Operations' own manifest/report validation — CreateJob's trust-policy check
        # had already cleared by then. Retry with a freshly created job rather than waiting on a
        # condition no API reports.
    assert status == "Suspended", (
        f"a ConfirmationRequired job settled into {status!r}, expected Suspended"
    )

    priority = s3c.update_job_priority(AccountId=account, JobId=job_id, Priority=42)
    assert priority["Priority"] == 42, (
        f"UpdateJobPriority returned priority {priority.get('Priority')!r}, expected 42"
    )
    described = s3c.describe_job(AccountId=account, JobId=job_id)["Job"]
    assert described["Priority"] == 42, (
        f"DescribeJob reports priority {described['Priority']!r} after the update to 42"
    )
    assert described["Status"] == "Suspended", (
        f"changing the priority moved the job to {described['Status']!r}; it should stay Suspended"
    )

    listed = {j["JobId"]: j for j in _all_jobs(s3c, account)}
    assert listed.get(job_id, {}).get("Priority") == 42, (
        f"ListJobs reports priority {listed.get(job_id, {}).get('Priority')!r} for the job"
    )

    cancel = s3c.update_job_status(
        AccountId=account, JobId=job_id, RequestedJobStatus="Cancelled",
        StatusUpdateReason="sim2real behav cancel",
    )
    assert cancel["Status"] == "Cancelled", (
        f"UpdateJobStatus(Cancelled) returned status {cancel.get('Status')!r}"
    )
    terminal = _poll_job_status(s3c, account, job_id, {"Cancelled", "Complete", "Failed"})
    assert terminal == "Cancelled", (
        f"the job settled into {terminal!r} after the cancel, expected Cancelled"
    )

    # A terminal job refuses a second status transition. The model declares JobStatusException
    # for this, but AWS answers InvalidRequest 400 "Requested job status forbidden".
    code, message = _error(
        lambda: s3c.update_job_status(
            AccountId=account, JobId=job_id, RequestedJobStatus="Ready"
        )
    )
    assert code == "InvalidRequest", (
        f"resuming a Cancelled job returned {code!r}, expected InvalidRequest"
    )
    assert message == "Requested job status forbidden", message
    final_status = s3c.describe_job(AccountId=account, JobId=job_id)["Job"]["Status"]
    assert final_status == "Cancelled", (
        f"the rejected resume attempt left the job in {final_status!r}, expected it to remain "
        "Cancelled"
    )


# ===== helpers =====

def _deadline(ctx, seconds: float) -> float:
    """A monotonic deadline ``seconds`` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else max(1.0, min(seconds, left - 5.0)))


def _error(fn):
    """The AWS error (code, message) raised by ``fn``. Raises if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error code was expected")


def _poll_job_status(s3c, account: str, job_id: str, wanted: set, attempts: int = 60) -> str:
    status = None
    for _ in range(attempts):
        status = s3c.describe_job(AccountId=account, JobId=job_id)["Job"]["Status"]
        if status in wanted:
            return status
        time.sleep(3)
    return status


def _all_jobs(s3c, account: str) -> list:
    out: list = []
    token = None
    while True:
        args = {"AccountId": account}
        if token:
            args["NextToken"] = token
        page = s3c.list_jobs(**args)
        out.extend(page.get("Jobs", []))
        token = page.get("NextToken")
        if not token:
            return out


def _cancel_job(s3c, account: str, job_id: str) -> None:
    """Drive a still-cancellable job to Cancelled so it stops running."""
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
                    "Resource": [
                        f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*",
                    ],
                }
            ],
        }),
    )
    # IAM propagation exposes no condition to poll (no API reports a policy is effective);
    # the CreateJob retry loop above is the wait, bounded by its own attempt count.
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
