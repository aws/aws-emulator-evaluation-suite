"""e2e-ota-update-lifecycle-to-job-execution."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "e2e-ota-update-lifecycle-to-job-execution"
GROUP = "e2e"
SERVICES = ["iot"]


def _mgmt_tags():
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-ota"}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An OTA update backed by a data stream spawns a real underlying IoT job with a queued
    execution for its target thing, and reaches CREATE_COMPLETE before both are torn down."""
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    iot = ctx.client("iot")

    bucket_name = ctx.unique_name("sim2real-ota-bucket-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket_name))
    object_key = "firmware.bin"
    s3.put_object(Bucket=bucket_name, Key=object_key, Body=b"sim2real-fake-firmware-bytes")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket_name, Key=object_key))

    role_name = ctx.unique_name("sim2real-ota-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": f"arn:aws:s3:::{bucket_name}/*"}
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="ota-s3-read", PolicyDocument=json.dumps(access_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="ota-s3-read"))
    # The OTA update service assumes this role to create the underlying IoT job -- it needs
    # iot:CreateJob (and signer:DescribeSigningJob) via the AWS-managed OTA-update policy, not
    # just S3 read access to the firmware object.
    ota_managed_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSIoTOTAUpdate"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=ota_managed_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=ota_managed_policy_arn))
    iam.get_waiter("role_exists").wait(RoleName=role_name, WaiterConfig={"Delay": 2, "MaxAttempts": 10})

    thing_name = ctx.unique_name("sim2real-ota-thing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    stream_id = ctx.unique_name("sim2real-ota-stream-")
    _retry_on_role_propagation(
        lambda: iot.create_stream(
            streamId=stream_id,
            files=[{"fileId": 0, "s3Location": {"bucket": bucket_name, "key": object_key}}],
            roleArn=role_arn,
            tags=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()],
        )
    )
    ctx.on_cleanup(lambda: iot.delete_stream(streamId=stream_id))

    ota_update_id = ctx.unique_name("sim2real-ota-update-")
    iot.create_ota_update(
        otaUpdateId=ota_update_id,
        targets=[thing_arn],
        targetSelection="SNAPSHOT",
        files=[
            {
                "fileName": object_key,
                "fileVersion": "1",
                "fileLocation": {"stream": {"streamId": stream_id, "fileId": 0}},
            }
        ],
        roleArn=role_arn,
        # No `tags=` here: CreateOTAUpdate propagates tags onto the underlying AFR_OTA-*
        # Job it creates via the assumed roleArn, which would then also need iot:TagResource.
        # Tagging the update's own directly-owned resources is enough for the tag search.
    )
    ctx.on_cleanup(lambda: iot.delete_ota_update(otaUpdateId=ota_update_id, forceDeleteAWSJob=True))

    # awsIotJobId can be absent from the immediate CreateOTAUpdate response while the update is
    # still CREATE_PENDING; poll GetOTAUpdate until the underlying job id actually shows up
    # rather than assuming it's synchronous.
    created_info = _poll_until(
        lambda: iot.get_ota_update(otaUpdateId=ota_update_id)["otaUpdateInfo"],
        lambda info: info.get("awsIotJobId") or info["otaUpdateStatus"] == "CREATE_FAILED",
        timeout_s=60,
        interval_s=3,
    )
    job_id = created_info.get("awsIotJobId")
    assert job_id, f"OTA update never acquired an underlying AWS IoT job id: {created_info}"

    listing = iot.list_ota_updates()["otaUpdates"]
    assert any(u["otaUpdateId"] == ota_update_id for u in listing), (
        f"expected {ota_update_id!r} in ListOTAUpdates, got {[u['otaUpdateId'] for u in listing]!r}"
    )

    job = iot.describe_job(jobId=job_id)["job"]
    assert job["targets"] == [thing_arn], f"expected job targets [{thing_arn!r}], got {job['targets']!r}"

    executions = iot.list_job_executions_for_job(jobId=job_id)["executionSummaries"]
    assert len(executions) == 1, f"expected exactly 1 job execution, got {executions!r}"
    assert executions[0]["thingArn"] == thing_arn, (
        f"expected execution for {thing_arn!r}, got {executions[0]!r}"
    )
    # The target thing never actually connects, so its execution stays queued rather than
    # advancing -- assert the target's own reported state rather than just its presence.
    execution_status = executions[0]["jobExecutionSummary"]["status"]
    assert execution_status == "QUEUED", (
        f"expected the never-connected thing's execution to be QUEUED, got {execution_status!r}"
    )

    final = _poll_until(
        lambda: iot.get_ota_update(otaUpdateId=ota_update_id)["otaUpdateInfo"],
        lambda info: info["otaUpdateStatus"] in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=90,
        interval_s=3,
    )
    assert final["otaUpdateStatus"] == "CREATE_COMPLETE", (
        f"OTA update did not reach CREATE_COMPLETE: {final.get('errorInfo')}"
    )
    assert final["awsIotJobId"] == job_id, (
        f"expected the completed OTA update to keep job id {job_id!r}, got {final['awsIotJobId']!r}"
    )



def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last value: {value!r})")


def _retry_on_role_propagation(fn, *, timeout_s: float = 30, interval_s: float = 3):
    """IAM role trust/permission propagation can lag a few seconds after CreateRole /
    PutRolePolicy -- retry the IoT call until the new role is actually assumable."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if code in ("InvalidRequestException",) or "Permission denied" in str(exc) or "AccessDenied" in str(exc):
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise AssertionError(f"role never became assumable within {timeout_s}s: {last_exc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
