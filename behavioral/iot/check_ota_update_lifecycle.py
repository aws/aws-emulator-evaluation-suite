"""ota-update-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ota-update-lifecycle"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOTAUpdate -> GetOTAUpdate -> ListOTAUpdates -> DeleteOTAUpdate drives the
    update through CREATE_COMPLETE, shows up in the account listing while it exists, and
    is fully removed (GetOTAUpdate -> ResourceNotFoundException) after delete."""
    iot = ctx.client("iot")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx, s3)
    s3.put_object(Bucket=bucket, Key="firmware.bin", Body=b"sim2real-fake-firmware-bytes")

    role_arn = _create_service_role(ctx, iam, "iot.amazonaws.com", ["arn:aws:iam::aws:policy/service-role/AWSIoTOTAUpdate"])
    _grant_s3_read(ctx, iam, role_arn, bucket)

    thing_name = ctx.unique_name("sim2real-iot-ota-thing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    # IAM role trust propagation for a brand-new role can lag by tens of seconds; AWS IoT's
    # own attempt to assume the role for the OTA job can race ahead of that propagation and
    # fail with a terminal CREATE_FAILED ("Permission denied when attempting to assume
    # role"). A failed update's own removal is a slow async reconciliation (measured: it can
    # outlast any bound reasonable to block a retry on -- see the identical situation on the
    # final delete below), so a retry reuses the same otaUpdateId; each attempt gets a fresh
    # id, and the abandoned one's deletion is fired but never waited on.
    attempted_ota_ids = []
    ctx.on_cleanup(lambda: [_delete_ota_update_quiet(iot, oid) for oid in attempted_ota_ids])

    final = None
    create_resp = None
    ota_id = None
    deadline = time.monotonic() + 90.0
    while True:
        attempt_id = ctx.unique_name("sim2real-ota-")
        attempted_ota_ids.append(attempt_id)
        create_resp = _retry_while(
            lambda attempt_id=attempt_id: iot.create_ota_update(
                otaUpdateId=attempt_id,
                targets=[thing_arn],
                targetSelection="SNAPSHOT",
                protocols=["HTTP"],
                roleArn=role_arn,
                files=[
                    {
                        "fileName": "firmware.bin",
                        "fileLocation": {"s3Location": {"bucket": bucket, "key": "firmware.bin"}},
                    }
                ],
            ),
            retry_codes={"InvalidRequestException"},
            timeout_s=30.0,
        )
        assert create_resp["otaUpdateId"] == attempt_id

        final = _poll_until(
            lambda attempt_id=attempt_id: iot.get_ota_update(otaUpdateId=attempt_id)["otaUpdateInfo"],
            lambda info: info["otaUpdateStatus"] in ("CREATE_COMPLETE", "CREATE_FAILED"),
            timeout_s=90.0,
            interval_s=3.0,
        )
        if final["otaUpdateStatus"] == "CREATE_COMPLETE":
            ota_id = attempt_id
            break
        error_info = final.get("errorInfo", {})
        message = error_info.get("message", "").lower()
        retryable = "assume role" in message or "access denied" in message or "passrole" in message
        if not retryable or time.monotonic() >= deadline:
            raise AssertionError(json.dumps(error_info))
        try:
            iot.delete_ota_update(otaUpdateId=attempt_id, deleteStream=True, forceDeleteAWSJob=True)
        except ClientError:
            pass

    job_id = final["awsIotJobId"]
    if create_resp.get("awsIotJobId"):
        assert create_resp["awsIotJobId"] == job_id


    ota_ids = set()
    next_token = None
    for _ in range(50):
        kwargs = {"nextToken": next_token} if next_token else {}
        page = iot.list_ota_updates(**kwargs)
        ota_ids.update(u["otaUpdateId"] for u in page.get("otaUpdates", []))
        next_token = page.get("nextToken")
        if not next_token or ota_id in ota_ids:
            break
    assert ota_id in ota_ids

    # The underlying AWS IoT job never completes (no real device ever picks it up). Cancel
    # it explicitly and wait for it to reach a terminal status before deleting the OTA
    # update -- otherwise the delete can be left reconciling against a job that's still
    # IN_PROGRESS even with forceDeleteAWSJob set.
    try:
        iot.cancel_job(jobId=job_id, comment="sim2real-behav-cleanup", force=True)
    except ClientError:
        pass
    _poll_until(
        lambda: iot.describe_job(jobId=job_id)["job"]["status"],
        lambda s: s in ("CANCELED", "COMPLETED", "DELETION_IN_PROGRESS"),
        timeout_s=60.0,
        interval_s=3.0,
    )

    _retry_while(
        lambda: iot.delete_ota_update(otaUpdateId=ota_id, deleteStream=True, forceDeleteAWSJob=True),
        retry_codes={"InvalidRequestException", "ThrottlingException"},
        timeout_s=30.0,
    )

    # DeleteOTAUpdate passes through DELETE_IN_PROGRESS before GetOTAUpdate stops finding the
    # record; any other state on the way is a failure.
    expected_gone = f"Requested otaUpdateJob {ota_id} does not exist"
    deadline = time.monotonic() + 300.0
    while True:
        state, message = _error_code_or_status(iot, ota_id)
        if state != "DELETE_IN_PROGRESS" or time.monotonic() >= deadline:
            break
        time.sleep(5.0)
    if state == "DELETE_FAILED":
        info = iot.get_ota_update(otaUpdateId=ota_id)["otaUpdateInfo"]
        raise AssertionError(f"DELETE_FAILED: {json.dumps(info.get('errorInfo', {}))}")
    assert state == "ResourceNotFoundException", f"expected the deleted OTA update to be gone, last {state!r}"
    assert message == expected_gone, f"expected message {expected_gone!r}, got {message!r}"


def _error_code_or_status(iot, ota_id):
    """Return (status, None) while the update exists, else the (code, message) of the error."""
    try:
        info = iot.get_ota_update(otaUpdateId=ota_id)["otaUpdateInfo"]
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    return info["otaUpdateStatus"], None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_while(fn, retry_codes, timeout_s=20.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _create_bucket(ctx, s3):
    bucket = ctx.unique_name("sim2real-iot-ota-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket_quiet(s3, bucket))
    return bucket


def _delete_bucket_quiet(s3, bucket):
    try:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _create_service_role(ctx, iam, trust_service, managed_policy_arns=None):
    role_name = ctx.unique_name("sim2real-iot-ota-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
    for policy_arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            for policy_arn in managed_policy_arns or []:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-s3-read")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _grant_s3_read(ctx, iam, role_arn, bucket):
    role_name = role_arn.split("/")[-1]
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}"],
            },
            {
                # The OTA job creation flow has AWS IoT (running as this role) pass this
                # same role along internally, so the role needs permission to pass itself
                # to the iot service.
                "Effect": "Allow",
                "Action": ["iam:PassRole"],
                "Resource": [role_arn],
                "Condition": {"StringEquals": {"iam:PassedToService": "iot.amazonaws.com"}},
            },
            {
                # DeleteOTAUpdate (with forceDeleteAWSJob) has AWS IoT, running as this
                # same role, delete the underlying AWS IoT job it created.
                "Effect": "Allow",
                "Action": ["iot:DeleteJob", "iot:DeleteJobExecution", "iot:CancelJob"],
                "Resource": ["*"],
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-s3-read", PolicyDocument=json.dumps(policy_doc)
    )


def _delete_ota_update_quiet(iot, ota_id):
    try:
        iot.delete_ota_update(otaUpdateId=ota_id, deleteStream=True, forceDeleteAWSJob=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
