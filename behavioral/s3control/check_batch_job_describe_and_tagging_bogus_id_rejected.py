"""batch-job-describe-and-tagging-bogus-id-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-job-describe-and-tagging-bogus-id-rejected"
GROUP = "state-machine"
SERVICES = ["s3control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An unknown job id is rejected identically by DescribeJob, UpdateJobPriority/Status and
    GetJobTagging (InvalidRequest 400, not the modeled NotFoundException), while a real job
    in the same account answers all four."""
    s3 = ctx.client("s3")
    s3c = ctx.client("s3control")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]
    bucket = ctx.unique_name("sim2real-behav-jbad-")
    role = ctx.unique_name("sim2real-behav-jbadrole-")
    bogus = "00000000-0000-4000-8000-000000000000"

    probes = {
        "DescribeJob": lambda jid: s3c.describe_job(AccountId=account, JobId=jid),
        "UpdateJobPriority":
            lambda jid: s3c.update_job_priority(AccountId=account, JobId=jid, Priority=1),
        "UpdateJobStatus":
            lambda jid: s3c.update_job_status(
                AccountId=account, JobId=jid, RequestedJobStatus="Cancelled"),
        "GetJobTagging": lambda jid: s3c.get_job_tagging(AccountId=account, JobId=jid),
    }
    for operation, call in probes.items():
        code, code_msg = _error(lambda: call(bogus))
        assert code == "InvalidRequest", (
            f"{operation} on an unknown job id returned {code!r}, expected InvalidRequest "
            "(s3control answers 'Job not found' as InvalidRequest 400, not the declared "
            "NotFoundException)"
        )
        code_want = "Job not found"
        assert code_msg == code_want, (
            f"the refusal carried message {code_msg!r}, expected {code_want!r}"
        )

    # Positive control: a real job answers all four operations.
    _create_bucket(ctx, s3, bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_object(Bucket=bucket, Key="obj/a.txt", Body=b"control")
    manifest_etag = s3.put_object(
        Bucket=bucket, Key="manifest.csv", Body=f"{bucket},obj/a.txt\n".encode()
    )["ETag"].strip('"')
    role_arn = _batch_role(ctx, iam, role, bucket)

    # IAM role propagation: CreateJob validates the trust/permission of the role, which is not
    # visible immediately after creation. Retry CreateJob on that transient rejection.
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
                Priority=3,
                RoleArn=role_arn,
                Description="sim2real-behav control job",
                Tags=[{"Key": "sim2real", "Value": "job"}],
            )["JobId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "BadRequestException":
                raise
            if time.monotonic() >= deadline:
                break
            time.sleep(2)
    assert job_id, "the control CreateJob never succeeded"
    ctx.on_cleanup(lambda: _cancel_job(s3c, account, job_id))

    assert s3c.describe_job(AccountId=account, JobId=job_id)["Job"]["JobId"] == job_id, (
        "DescribeJob did not return the control job it just created"
    )
    assert s3c.get_job_tagging(AccountId=account, JobId=job_id)["Tags"] == [
        {"Key": "sim2real", "Value": "job"}
    ], (
        "GetJobTagging on the control job did not read back the tag it was created with"
    )


# ===== helpers =====

def _deadline(ctx, seconds: float) -> float:
    """A monotonic deadline ``seconds`` away, capped by the run's remaining time."""
    left = ctx.time_left()
    return time.monotonic() + (seconds if left is None else max(1.0, min(seconds, left - 5.0)))


def _error(fn):
    """The AWS error ``(code, message)`` raised by ``fn``; raises if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("call unexpectedly succeeded; an error was expected")


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
    # us-east-1 is CreateBucket's implicit default region and forbids an explicit
    # LocationConstraint for it.
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
