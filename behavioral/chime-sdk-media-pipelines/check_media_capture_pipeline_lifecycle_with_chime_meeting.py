"""media-capture-pipeline-lifecycle-with-chime-meeting."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "media-capture-pipeline-lifecycle-with-chime-meeting"
GROUP = "state"
SERVICES = ["chime-sdk-media-pipelines"]

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A media capture pipeline sourced from a real Chime SDK meeting actually starts
    capturing: Status transitions Initializing -> InProgress, the generic GetMediaPipeline
    accessor reflects the same state, and deleting the pipeline eventually removes it."""
    meetings = ctx.client("chime-sdk-meetings")
    chime = ctx.client("chime-sdk-media-pipelines")
    _ensure_service_linked_role(ctx)

    meeting = meetings.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2realmtg")[:64],
        MediaRegion=ctx.region,
        ExternalMeetingId=ctx.unique_name("sim2real-ext-")[:64],
        Tags=[{"Key": "sim2real-env", "Value": "test"}, {"Key": "sim2real-owner", "Value": "behavioral"}],
    )["Meeting"]
    meeting_arn = meeting["MeetingArn"]
    meeting_id = meeting["MeetingId"]
    ctx.on_cleanup(lambda: meetings.delete_meeting(MeetingId=meeting_id))

    bucket_arn = _create_capture_bucket(ctx)

    pipeline = _create_pipeline_with_role_propagation_retry(
        chime,
        SourceType="ChimeSdkMeeting",
        SourceArn=meeting_arn,
        SinkType="S3Bucket",
        SinkArn=bucket_arn,
        Tags=[{"Key": "sim2real-env", "Value": "test"}, {"Key": "sim2real-owner", "Value": "behavioral"}],
    )["MediaCapturePipeline"]
    pipeline_id = pipeline["MediaPipelineId"]
    assert pipeline["Status"] == "Initializing", f"expected Initializing on create, got {pipeline['Status']!r}"

    def _try_delete_pipeline():
        try:
            chime.delete_media_capture_pipeline(MediaPipelineId=pipeline_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_try_delete_pipeline)

    status = _poll_until(
        lambda: chime.get_media_capture_pipeline(MediaPipelineId=pipeline_id)["MediaCapturePipeline"][
            "Status"
        ],
        lambda s: s in ("InProgress", "Failed"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert status == "InProgress", f"capture pipeline never reached InProgress, ended at {status}"

    generic = chime.get_media_pipeline(MediaPipelineId=pipeline_id)["MediaPipeline"]
    generic_capture = generic["MediaCapturePipeline"]
    assert generic_capture["Status"] == "InProgress", (
        f"generic GetMediaPipeline accessor disagrees with GetMediaCapturePipeline: "
        f"expected InProgress, got {generic_capture['Status']!r}"
    )
    assert generic_capture["SourceArn"] == meeting_arn, (
        f"expected SourceArn {meeting_arn!r}, got {generic_capture['SourceArn']!r}"
    )
    assert generic_capture["SinkArn"] == bucket_arn, (
        f"expected SinkArn {bucket_arn!r}, got {generic_capture['SinkArn']!r}"
    )

    chime.delete_media_capture_pipeline(MediaPipelineId=pipeline_id)

    gone = _await_client_error(
        lambda: chime.get_media_capture_pipeline(MediaPipelineId=pipeline_id),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert gone["Code"] == "NotFoundException", f"expected NotFoundException after delete, got {gone!r}"
    assert gone["Message"] == "Unable to find the requested identifier", (
        f"unexpected NotFoundException message after delete: {gone['Message']!r}"
    )


def _ensure_service_linked_role(ctx) -> None:
    """CreateMediaCapturePipeline requires the AWSServiceRoleForAmazonChimeSDKMediaPipelines
    service-linked role to exist in the account; create it idempotently (ignore
    InvalidInputException if it already exists)."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="mediapipelines.chime.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInputException", "InvalidInput"):
            raise


def _create_pipeline_with_role_propagation_retry(chime, timeout_s: float = 60.0, interval_s: float = 5.0, **kwargs):
    """The AWSServiceRoleForAmazonChimeSDKMediaPipelines service-linked role just created by
    _ensure_service_linked_role can take a few seconds to propagate; retry only the specific
    BadRequestException that names the missing role, never any other rejection."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return chime.create_media_capture_pipeline(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if (
                err["Code"] != "BadRequestException"
                or "service-linked role" not in err.get("Message", "")
                or time.monotonic() >= deadline
            ):
                raise
            time.sleep(interval_s)


def _create_capture_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket_name = ctx.unique_name("sim2real-chimecap-").lower().replace("_", "-")

    # us-east-1 is a CreateBucket API quirk (S3 rejects an explicit LocationConstraint for
    # it), not an assumption about which region this check runs in.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name,
        Tagging={"TagSet": [{"Key": "sim2real-env", "Value": "test"}, {"Key": "sim2real-owner", "Value": "behavioral"}]},
    )

    policy = {
        "Version": "2012-10-17",
        "Id": "AWSChimeMediaCaptureBucketPolicy",
        "Statement": [
            {
                "Sid": "AWSChimeMediaCaptureBucketPolicy",
                "Effect": "Allow",
                "Principal": {"Service": "mediapipelines.chime.amazonaws.com"},
                "Action": ["s3:PutObject", "s3:PutObjectAcl"],
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:chime:*:{account_id}:*"},
                },
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy))
    return f"arn:aws:s3:::{bucket_name}"


def _empty_and_delete_bucket(s3, bucket_name: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
            if objects:
                failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket_name)


def _await_client_error(fn, timeout_s: float, interval_s: float) -> dict:
    """Call fn() until it raises; return its botocore Error dict. A read that keeps
    SUCCEEDING past the deadline raises, so a pipeline that outlives its delete fails loudly."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"Get still succeeds {timeout_s}s after delete: {result!r}")
        time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
