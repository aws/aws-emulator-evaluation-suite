"""ota-update-lifecycle-and-delete-guard."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ota-update-lifecycle-and-delete-guard"
GROUP = "state-machine"
SERVICES = ["iot"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An OTA update reaches CREATE_COMPLETE; a plain DeleteOTAUpdate succeeds despite the active
    job but orphans it, while forceDeleteAWSJob also deletes the underlying job."""
    s3 = ctx.client("s3")
    iot = ctx.client("iot")

    bucket = ctx.unique_name("sim2real-iot-otalc").lower()
    _create_bucket(ctx, s3, bucket)
    key = "firmware.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-fake-firmware")

    role_arn = _create_ota_role(ctx, bucket)

    thing_a = _create_thing(ctx, iot, "sim2real-iot-otalc-thing-a-")
    thing_b = _create_thing(ctx, iot, "sim2real-iot-otalc-thing-b-")

    ota_id_a = ctx.unique_name("sim2realotalca")
    job_id_a = _create_ota_update_retrying(
        ctx, iot, ota_id_a, thing_a, bucket, key, role_arn, timeout_s=120.0
    )
    ota_id_b = ctx.unique_name("sim2realotalcb")
    job_id_b = _create_ota_update_retrying(
        ctx, iot, ota_id_b, thing_b, bucket, key, role_arn, timeout_s=60.0
    )

    # neither job ever reaches a terminal state because the target thing is
    # never actually connected -- both stay IN_PROGRESS
    for label, job_id in (("a", job_id_a), ("b", job_id_b)):
        job_status = _poll_until(
            lambda job_id=job_id: iot.describe_job(jobId=job_id)["job"]["status"],
            lambda s: s in ("IN_PROGRESS", "COMPLETED", "CANCELED"),
            timeout_s=30,
        )
        assert job_status == "IN_PROGRESS", (
            f"expected job {label} to still be IN_PROGRESS (no device ever "
            f"connects), got {job_status!r}"
        )

    # A: a plain delete, no flags, succeeds despite the still-active job --
    # no VersionConflictException, no rejection of any kind.
    iot.delete_ota_update(otaUpdateId=ota_id_a)
    final_state_a = _poll_until(
        lambda: _status_or_not_found(iot, ota_id_a),
        lambda s: s == "ResourceNotFoundException",
        timeout_s=60,
    )
    assert final_state_a == "ResourceNotFoundException", (
        f"expected the unforced delete of {ota_id_a!r} to fully remove the "
        f"record, got {final_state_a!r}"
    )
    # ... but the job it spawned is orphaned: the unforced delete never
    # touches it.
    job_after_a = iot.describe_job(jobId=job_id_a)["job"]["status"]
    assert job_after_a == "IN_PROGRESS", (
        f"expected the unforced DeleteOTAUpdate to leave job {job_id_a!r} "
        f"orphaned and IN_PROGRESS, got {job_after_a!r}"
    )

    # B: forceDeleteAWSJob=True also succeeds, and additionally drives the
    # underlying job itself to deletion.
    iot.delete_ota_update(otaUpdateId=ota_id_b, forceDeleteAWSJob=True)
    final_state_b = _poll_until(
        lambda: _status_or_not_found(iot, ota_id_b),
        lambda s: s == "ResourceNotFoundException",
        timeout_s=60,
    )
    assert final_state_b == "ResourceNotFoundException", (
        f"expected the forced delete of {ota_id_b!r} to fully remove the "
        f"record, got {final_state_b!r}"
    )
    # The forced delete removes the job asynchronously: it may still read IN_PROGRESS or
    # DELETION_IN_PROGRESS for a while before DescribeJob stops finding it.
    deadline = time.monotonic() + 120.0
    while True:
        job_final_b = _job_status_or_not_found(iot, job_id_b)
        if job_final_b[0] not in _JOB_DELETING or time.monotonic() >= deadline:
            break
        time.sleep(3.0)
    assert job_final_b == ("ResourceNotFoundException", f"Job {job_id_b} cannot be found."), (
        f"expected forceDeleteAWSJob to also delete job {job_id_b!r}, last {job_final_b!r}"
    )

    # gone means unusable, not just absent from a read: a second delete on
    # the same, already-gone OTA update id must also fail rather than
    # silently no-op.
    redelete_code, redelete_message = _error_code(lambda: iot.delete_ota_update(otaUpdateId=ota_id_b))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a second DeleteOTAUpdate on the already-deleted "
        f"{ota_id_b!r} to report ResourceNotFoundException, got {redelete_code!r}"
    )
    expected_message = f"Requested otaUpdateJob {ota_id_b} does not exist"
    assert redelete_message == expected_message, (
        f"expected message {expected_message!r}, got {redelete_message!r}"
    )

    # A's job is orphaned by the plain delete; reap it so no live IoT job is left behind.
    _cancel_and_delete_job(iot, job_id_a)


def _create_bucket(ctx, s3, bucket):
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))


def _empty_and_delete_bucket(s3, bucket):
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_ota_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iot-otalc-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    role_arn = f"arn:aws:iam::{ctx.client('sts').get_caller_identity()['Account']}:role/{role_name}"
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {"Effect": "Allow", "Action": ["iot:*"], "Resource": "*"},
            {
                # The OTA flow passes this role along internally to create the job;
                # without this grant CreateOTAUpdate reaches CREATE_FAILED (iam:PassRole).
                "Effect": "Allow",
                "Action": ["iam:PassRole"],
                "Resource": [role_arn],
                "Condition": {"StringEquals": {"iam:PassedToService": "iot.amazonaws.com"}},
            },
        ],
    }
    policy_name = ctx.unique_name("sim2real-iot-otalc-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_thing(ctx, iot, prefix):
    thing_name = ctx.unique_name(prefix)
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))
    return thing_arn


def _create_ota_update_retrying(ctx, iot, ota_id, thing_arn, bucket, key, role_arn, timeout_s):
    """CreateOTAUpdate polled to a terminal status, retrying the whole cycle while IAM
    trust-policy propagation makes it CREATE_FAILED on role assumption."""
    ctx.on_cleanup(lambda: _delete_ota_update_quiet(iot, ota_id))
    deadline = time.monotonic() + timeout_s
    while True:
        create_resp = _retry_on_codes(
            lambda: iot.create_ota_update(
                otaUpdateId=ota_id,
                targets=[thing_arn],
                files=[{"fileName": key, "fileLocation": {"s3Location": {"bucket": bucket, "key": key}}}],
                roleArn=role_arn,
                targetSelection="SNAPSHOT",
            ),
            codes=("InvalidRequestException",),
            timeout_s=45,
        )
        assert create_resp["otaUpdateStatus"] in (
            "CREATE_PENDING",
            "CREATE_IN_PROGRESS",
            "CREATE_COMPLETE",
        ), f"CreateOTAUpdate returned unexpected otaUpdateStatus {create_resp['otaUpdateStatus']!r}"

        # CreateOTAUpdate is asynchronous -- the underlying AWS IoT job (and
        # its awsIotJobId) is only guaranteed to be populated once
        # GetOTAUpdate reflects a terminal creation status.
        final_info = _poll_until(
            lambda: iot.get_ota_update(otaUpdateId=ota_id)["otaUpdateInfo"],
            lambda info: info["otaUpdateStatus"] in ("CREATE_COMPLETE", "CREATE_FAILED"),
            timeout_s=90,
        )
        if final_info["otaUpdateStatus"] == "CREATE_COMPLETE":
            job_id = final_info["awsIotJobId"]
            ctx.on_cleanup(lambda job_id=job_id: _cancel_and_delete_job(iot, job_id))
            return job_id
        message = final_info.get("errorInfo", {}).get("message", "").lower()
        retryable = "assume role" in message or "permission denied" in message
        if not retryable or time.monotonic() >= deadline:
            raise AssertionError(
                f"expected CREATE_COMPLETE, got {final_info['otaUpdateStatus']!r} "
                f"(errorInfo={final_info.get('errorInfo')!r})"
            )
        while True:
            iot.delete_ota_update(otaUpdateId=ota_id, deleteStream=True, forceDeleteAWSJob=True)
            cleanup_state = _poll_until(
                lambda: _status_or_not_found(iot, ota_id),
                lambda s: s in ("ResourceNotFoundException", "DELETE_FAILED"),
                timeout_s=20,
            )
            if cleanup_state == "ResourceNotFoundException":
                break
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"the cleanup delete of failed create {ota_id!r} stayed "
                    f"DELETE_FAILED past the retry budget"
                )
            time.sleep(2)
        time.sleep(2)


def _delete_ota_update_quiet(iot, ota_id):
    """Teardown: an OTA update already deleted is clean; any other refusal raises."""
    try:
        iot.delete_ota_update(otaUpdateId=ota_id, deleteStream=True, forceDeleteAWSJob=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _cancel_and_delete_job(iot, job_id):
    """Cancel then force-delete a job. A missing job is clean; InvalidStateTransitionException means
    it is already terminal (cancel) or already being deleted (delete); a cancel refused because the
    job is in DELETION_IN_PROGRESS means its deletion is underway. Anything else raises."""
    tolerated = ("ResourceNotFoundException", "InvalidStateTransitionException")
    try:
        iot.cancel_job(jobId=job_id, comment="sim2real-behav-cleanup", force=True)
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] == "InvalidRequestException" and "DELETION_IN_PROGRESS" in error.get("Message", ""):
            return
        if error["Code"] not in tolerated:
            raise
    try:
        iot.delete_job(jobId=job_id, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in tolerated:
            raise


def _status_or_not_found(iot, ota_id):
    try:
        return iot.get_ota_update(otaUpdateId=ota_id)["otaUpdateInfo"]["otaUpdateStatus"]
    except ClientError as exc:
        return exc.response["Error"]["Code"]


_JOB_DELETING = {"IN_PROGRESS", "DELETION_IN_PROGRESS"}


def _job_status_or_not_found(iot, job_id):
    """(status, None) while the job exists, else the (code, message) of the error."""
    try:
        return iot.describe_job(jobId=job_id)["job"]["status"], None
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last}")


def _retry_on_codes(fn, codes, timeout_s=45.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in codes:
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _error_code(fn):
    """Return (code, message) of the ClientError fn() raises; fail loudly if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
