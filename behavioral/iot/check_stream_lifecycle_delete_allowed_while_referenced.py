"""stream-lifecycle-delete-allowed-while-referenced."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stream-lifecycle-delete-allowed-while-referenced"
GROUP = "state-machine"
SERVICES = ["iot"]


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteStream succeeds on a stream a CREATE_COMPLETE OTA update still references; the stream
    is then gone (describe and re-delete fail), the OTA update keeps the dangling streamId, and an
    unreferenced stream also deletes normally."""
    iot = ctx.client("iot")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-iotstream-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))

    key = "firmware.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"fake-firmware-bytes")

    role_name = ctx.unique_name("sim2real-streamrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:GetObject", "s3:GetObjectVersion"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            # DeleteOTAUpdate(forceDeleteAWSJob) deletes the OTA job AS this role, and the
            # AWSIoTOTAUpdate managed policy does not grant it; without this the teardown
            # strands the update in DELETE_FAILED.
            {
                "Effect": "Allow",
                "Action": ["iot:DescribeJob", "iot:CancelJob", "iot:DeleteJob"],
                "Resource": f"arn:aws:iot:{ctx.region}:{ctx.account}:job/*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="access", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="access"))
    # The OTA update service assumes this role to create the underlying AWS
    # IoT job (iot:CreateJob) and code-signing operations.
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSIoTOTAUpdate"
    )
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSIoTOTAUpdate"
        )
    )

    thing_name = ctx.unique_name("sim2real-otathing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    stream_id = ctx.unique_name("sim2real-stream-")

    def _create_stream():
        return iot.create_stream(
            streamId=stream_id,
            files=[{"fileId": 0, "s3Location": {"bucket": bucket, "key": key}}],
            roleArn=role_arn,
            tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    # IAM role propagation can take a few seconds
    result = _poll_until(
        lambda: _try(_create_stream),
        lambda r: r is not None,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert result is not None, "CreateStream never succeeded (role propagation timeout)"
    ctx.on_cleanup(lambda: _safe_delete_stream(iot, stream_id))

    ota_id = ctx.unique_name("sim2real-ota-")
    iot.create_ota_update(
        otaUpdateId=ota_id,
        targets=[thing_arn],
        roleArn=role_arn,
        protocols=["MQTT"],
        targetSelection="SNAPSHOT",
        files=[
            {
                "fileName": "firmware.bin",
                "fileType": 0,
                "fileLocation": {"stream": {"streamId": stream_id, "fileId": 0}},
            }
        ],
    )
    ctx.on_cleanup(lambda: _safe_delete_ota(iot, ota_id))

    # the OTA update's job is created asynchronously; the stream is referenced only once it exists
    ota_info = _poll_until(
        lambda: iot.get_ota_update(otaUpdateId=ota_id)["otaUpdateInfo"],
        lambda info: info["otaUpdateStatus"] in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=60.0,
        interval_s=3.0,
    )
    ota_status = ota_info["otaUpdateStatus"]
    assert ota_status == "CREATE_COMPLETE", (
        f"OTA update never completed creation, last status={ota_status}, "
        f"errorInfo={ota_info.get('errorInfo')}"
    )


    # AWS IoT does not treat an OTA update's reference as a delete-conflict for the stream
    iot.delete_stream(streamId=stream_id)
    code_gone, code_gone_message = _error(lambda: iot.describe_stream(streamId=stream_id))
    assert code_gone == "ResourceNotFoundException"
    assert code_gone_message == f"Requested stream {stream_id} does not exist in given account {ctx.account}", (
        f"expected the exact {code_gone} message, got {code_gone_message!r}"
    )

    redelete_code, redelete_code_message = _error(lambda: iot.delete_stream(streamId=stream_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a second delete of the same, already-gone stream to be "
        f"rejected, got {redelete_code}"
    )
    assert redelete_code_message == f"Requested stream {stream_id} does not exist in given account {ctx.account}", (
        f"expected the exact {redelete_code} message, got {redelete_code_message!r}"
    )

    # the OTA update is not retroactively invalidated; its file entry keeps the dangling streamId
    still_there = iot.get_ota_update(otaUpdateId=ota_id)["otaUpdateInfo"]
    dangling_stream_id = still_there["otaUpdateFiles"][0]["fileLocation"]["stream"]["streamId"]
    assert dangling_stream_id == stream_id, (
        f"expected the OTA update's file reference to still point at the "
        f"deleted stream {stream_id!r}, got {dangling_stream_id!r}"
    )

    control_key = f"control-{uuid.uuid4().hex}.bin"
    s3.put_object(Bucket=bucket, Key=control_key, Body=b"unused-bytes")
    control_stream_id = ctx.unique_name("sim2real-stream-control-")
    _poll_until(
        lambda: _try(
            lambda: iot.create_stream(
                streamId=control_stream_id,
                files=[{"fileId": 0, "s3Location": {"bucket": bucket, "key": control_key}}],
                roleArn=role_arn,
                tags=[{"Key": "sim2real", "Value": CHECK}],
            )
        ),
        lambda r: r is not None,
        timeout_s=30.0,
        interval_s=3.0,
    )
    iot.delete_stream(streamId=control_stream_id)
    code_control_gone, code_control_gone_message = _error(lambda: iot.describe_stream(streamId=control_stream_id))
    assert code_control_gone == "ResourceNotFoundException"
    assert code_control_gone_message == f"Requested stream {control_stream_id} does not exist in given account {ctx.account}", (
        f"expected the exact {code_control_gone} message, got {code_control_gone_message!r}"
    )


def _try(fn):
    try:
        return fn()
    except ClientError:
        return None


def _safe_delete_stream(iot, stream_id: str) -> None:
    try:
        iot.delete_stream(streamId=stream_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_ota(iot, ota_id: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> None:
    """Delete the OTA update and wait until it is gone: DeleteOTAUpdate is asynchronous and assumes
    the OTA role, so deleting the role first strands the update in DELETE_FAILED."""
    try:
        iot.delete_ota_update(otaUpdateId=ota_id, forceDeleteAWSJob=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            info = iot.get_ota_update(otaUpdateId=ota_id)["otaUpdateInfo"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        status = info.get("otaUpdateStatus")
        if status == "DELETE_FAILED":
            raise AssertionError(f"OTA update {ota_id} teardown ended DELETE_FAILED: {info.get('errorInfo')}")
        if time.monotonic() >= deadline:
            raise AssertionError(f"OTA update {ota_id} still {status} after {timeout_s:.0f}s of teardown")
        time.sleep(interval_s)


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    try:
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
