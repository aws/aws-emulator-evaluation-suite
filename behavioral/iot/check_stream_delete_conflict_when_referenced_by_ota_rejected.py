"""stream-delete-conflict-when-referenced-by-ota-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stream-delete-conflict-when-referenced-by-ota-rejected"
GROUP = "overly-permissive"
SERVICES = ["iot"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A duplicate CreateStream is rejected without touching the original; DeleteStream succeeds
    while an OTA update references the stream (leaving a dangling streamId), and a repeat
    delete is rejected with ResourceNotFoundException."""
    s3 = ctx.client("s3")
    iot = ctx.client("iot")

    bucket = ctx.unique_name("sim2real-iot-otastrm").lower()
    _create_bucket(ctx, s3, bucket)
    key = "firmware.bin"
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-fake-firmware")

    role_arn = _create_ota_role(ctx, bucket)

    stream_id = ctx.unique_name("sim2realstrm")
    _retry_on_codes(
        lambda: iot.create_stream(
            streamId=stream_id,
            files=[{"fileId": 0, "s3Location": {"bucket": bucket, "key": key}}],
            roleArn=role_arn,
            tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
        # newly-created role/policy propagation is eventually consistent: IoT
        # can reject the S3 read with either code while it catches up
        codes=("InvalidRequestException", "UnauthorizedException"),
        timeout_s=45,
    )
    stream_deleted = {"done": False}

    def _cleanup_stream():
        if not stream_deleted["done"]:
            _safe_delete_stream(iot, stream_id)

    ctx.on_cleanup(_cleanup_stream)

    # negative: re-using the same streamId is rejected, and the original
    # stream's state is untouched by the rejected attempt. Immediately after
    # the first create, AWS IoT can transiently answer InvalidRequestException
    # instead of the terminal ResourceAlreadyExistsException -- retry through
    # that window rather than pinning to whichever response lands first.
    dup_code, dup_code_message = _error_with_retry(
        lambda: iot.create_stream(
            streamId=stream_id,
            files=[{"fileId": 0, "s3Location": {"bucket": bucket, "key": key}}],
            roleArn=role_arn,
        ),
        transient_codes=("InvalidRequestException",),
        timeout_s=30,
    )
    assert dup_code == "ResourceAlreadyExistsException", (
        f"expected re-creating streamId {stream_id!r} while it still exists to be "
        f"rejected as already-existing, got {dup_code!r}"
    )
    assert dup_code_message == f"Requested stream {stream_id} stream already exists.", (
        f"expected the exact {dup_code} message, got {dup_code_message!r}"
    )

    # the rejected duplicate create must not have disturbed the original stream's definition
    unchanged = iot.describe_stream(streamId=stream_id)["streamInfo"]
    assert unchanged["files"][0]["s3Location"] == {"bucket": bucket, "key": key}, (
        f"expected the original stream's file location to be untouched by the "
        f"rejected duplicate create, got {unchanged['files'][0]['s3Location']}"
    )

    thing_name = ctx.unique_name("sim2real-iot-otastrm-thing-")
    thing_arn = iot.create_thing(thingName=thing_name)["thingArn"]
    ctx.on_cleanup(lambda: iot.delete_thing(thingName=thing_name))

    ota_id = ctx.unique_name("sim2realota")
    _retry_on_codes(
        lambda: iot.create_ota_update(
            otaUpdateId=ota_id,
            targets=[thing_arn],
            files=[
                {
                    "fileName": "firmware.bin",
                    "fileLocation": {"stream": {"streamId": stream_id, "fileId": 0}},
                }
            ],
            roleArn=role_arn,
            targetSelection="SNAPSHOT",
            tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
        codes=("InvalidRequestException",),
        timeout_s=45,
    )
    ota_deleted = {"done": False}

    def _cleanup_ota():
        if not ota_deleted["done"]:
            try:
                iot.delete_ota_update(otaUpdateId=ota_id, forceDeleteAWSJob=True)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise

    ctx.on_cleanup(_cleanup_ota)

    final_info = _poll_until(
        lambda: iot.get_ota_update(otaUpdateId=ota_id)["otaUpdateInfo"],
        lambda info: info["otaUpdateStatus"] in ("CREATE_COMPLETE", "CREATE_FAILED"),
        timeout_s=90,
    )
    assert final_info["otaUpdateStatus"] == "CREATE_COMPLETE", (
        f"expected the prerequisite OTA update {ota_id!r} to finish creation, got "
        f"{final_info['otaUpdateStatus']!r}, errorInfo={final_info.get('errorInfo')}"
    )
    job_id = final_info.get("awsIotJobId")

    # DeleteStream succeeds even while the OTA update above still references
    # this stream by ID -- real AWS does not guard this cross-reference.
    iot.delete_stream(streamId=stream_id)
    stream_deleted["done"] = True

    not_found_code, not_found_code_message = _error(lambda: iot.describe_stream(streamId=stream_id))
    assert not_found_code == "ResourceNotFoundException", (
        f"expected the deleted stream {stream_id!r} to be gone, got {not_found_code!r}"
    )
    assert not_found_code_message == f"Requested stream {stream_id} does not exist in given account {ctx.account}", (
        f"expected the exact {not_found_code} message, got {not_found_code_message!r}"
    )

    # the OTA update is unaffected by the stream's deletion -- its file
    # metadata still shows the now-dangling streamId reference
    still_there = iot.get_ota_update(otaUpdateId=ota_id)["otaUpdateInfo"]
    dangling = still_there["otaUpdateFiles"][0]["fileLocation"]["stream"]["streamId"]
    assert dangling == stream_id, (
        f"expected the OTA update's file metadata to still hold the now-dangling "
        f"streamId {stream_id!r} after the stream's deletion, got {dangling!r}"
    )

    # a second delete of the already-gone stream is rejected, not a silent no-op
    redelete_code, redelete_code_message = _error(lambda: iot.delete_stream(streamId=stream_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected re-deleting the already-gone stream {stream_id!r} to be "
        f"rejected, got {redelete_code!r}"
    )
    assert redelete_code_message == f"Requested stream {stream_id} does not exist in given account {ctx.account}", (
        f"expected the exact {redelete_code} message, got {redelete_code_message!r}"
    )

    iot.delete_ota_update(otaUpdateId=ota_id, forceDeleteAWSJob=True)
    ota_deleted["done"] = True

    if job_id:
        try:
            iot.delete_job(jobId=job_id, force=True)
        except ClientError:
            pass


def _create_bucket(ctx, s3, bucket):
    region = ctx.region
    if region == "us-east-1":
        # us-east-1 is the one region where CreateBucket rejects an explicit
        # LocationConstraint -- this is an S3 API quirk, not a pinned region.
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
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _create_ota_role(ctx, bucket):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iot-ota-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetBucketLocation"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {"Effect": "Allow", "Action": ["iot:*"], "Resource": "*"},
        ],
    }
    policy_name = ctx.unique_name("sim2real-iot-ota-policy-")
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _safe_delete_stream(iot, stream_id):
    try:
        iot.delete_stream(streamId=stream_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises rather
    than returning a falsy sentinel, so a target that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _error_with_retry(fn, transient_codes, timeout_s=30.0, interval_s=2.0):
    """Like _error, but retries through transient codes and returns the settled (code, message)."""
    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        last = _error(fn)
        if last[0] not in transient_codes:
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
