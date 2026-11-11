"""get-media-pipeline-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-media-pipeline-not-found"
GROUP = "errors"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMediaPipeline on a nonexistent MediaPipelineId fails with NotFoundException
    "Unable to find the requested identifier", while the same call on a freshly created
    media capture pipeline returns that pipeline's id."""
    chime = ctx.client("chime-sdk-media-pipelines")
    meetings = ctx.client("chime-sdk-meetings")
    s3 = ctx.client("s3")
    teardown = _Teardown()
    _ensure_service_linked_role(ctx)

    bogus_id = "00000000-0000-0000-0000-000000000000"
    error = _client_error(lambda: chime.get_media_pipeline(MediaPipelineId=bogus_id))
    assert error["Code"] == "NotFoundException", f"actual error: {error!r}"
    assert error["Message"] == "Unable to find the requested identifier", (
        f"unexpected NotFoundException message: {error['Message']!r}"
    )

    meeting = meetings.create_meeting(
        ClientRequestToken=ctx.unique_name("sim2realmtg")[:64],
        MediaRegion=ctx.region,
        ExternalMeetingId=ctx.unique_name("sim2real-ext-")[:64],
        Tags=[{"Key": "sim2real-env", "Value": "test"}],
    )["Meeting"]
    meeting_id = meeting["MeetingId"]
    meeting_arn = meeting["MeetingArn"]
    ctx.on_cleanup(lambda: meetings.delete_meeting(MeetingId=meeting_id))

    bucket_arn = _create_capture_bucket(ctx, s3, teardown)

    pipeline = _create_pipeline_with_retry(
        chime,
        SourceType="ChimeSdkMeeting",
        SourceArn=meeting_arn,
        SinkType="S3Bucket",
        SinkArn=bucket_arn,
        Tags=[{"Key": "sim2real-env", "Value": "test"}],
    )["MediaCapturePipeline"]
    pipeline_id = pipeline["MediaPipelineId"]
    ctx.on_cleanup(lambda: _try_delete_pipeline(chime, pipeline_id))

    # positive control: the identical GetMediaPipeline call, against a real id, resolves
    generic = chime.get_media_pipeline(MediaPipelineId=pipeline_id)["MediaPipeline"]
    fetched_id = generic["MediaCapturePipeline"]["MediaPipelineId"]
    assert fetched_id == pipeline_id, f"expected {pipeline_id}, got {fetched_id}"


def _create_capture_bucket(ctx, s3, teardown) -> str:
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket_name = ctx.unique_name("sim2real-chimecap-").lower().replace("_", "-")

    if ctx.region == "us-east-1":
        # S3 API quirk, not a region pin: LocationConstraint must be omitted for us-east-1.
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name, teardown))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-env", "Value": "test"}]})

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


#: Seconds every teardown of one run shares: the suite's 900 s cleanup budget less a 120 s margin.
_CLEANUP_S = 780.0


class _Teardown:
    """One deadline for all of a run's teardowns, started when the first of them runs."""

    def __init__(self) -> None:
        self._at = None

    def deadline(self) -> float:
        if self._at is None:
            self._at = time.monotonic() + _CLEANUP_S
        return self._at


def _empty_and_delete_bucket(s3, bucket_name: str, teardown) -> None:
    """Empty and delete the bucket, emptying it again while late capture objects keep it non-empty."""
    while True:
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket_name):
                objects = [{"Key": obj["Key"]} for obj in page.get("Contents", [])]
                if objects:
                    failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket_name)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NoSuchBucket":
                return
            if code != "BucketNotEmpty" or time.monotonic() >= teardown.deadline():
                raise
        time.sleep(2)


def _create_pipeline_with_retry(chime, timeout_s: float = 60.0, interval_s: float = 5.0, **kwargs):
    """A freshly created AWSServiceRoleForAmazonChimeSDKMediaPipelines service-linked role
    can take a few seconds to propagate; retry the specific "create a service-linked role"
    BadRequestException until it does, or the window closes."""
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


def _try_delete_pipeline(chime, pipeline_id: str) -> None:
    try:
        chime.delete_media_capture_pipeline(MediaPipelineId=pipeline_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


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


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises, so a
    target that accepts what AWS refuses fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


