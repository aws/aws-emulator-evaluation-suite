"""kinesis-video-stream-pool-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-video-stream-pool-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second Kinesis Video Stream pool with an existing PoolName fails with BadRequestException
    "Media Pipeline Kinesis Video Stream Pool already exists with <name> name", the original pool
    stays the only one with retention 2 h, and a pool under another name is created."""
    chime = ctx.client("chime-sdk-media-pipelines")
    teardown = _Teardown()
    _ensure_service_linked_role(ctx)
    pool_name = ctx.unique_name("sim2real-kvsdup-")

    first = _create_pool_with_retry(
        ctx,
        chime,
        PoolName=pool_name,
        StreamConfiguration={"Region": ctx.region, "DataRetentionInHours": 2},
    )["KinesisVideoStreamPoolConfiguration"]
    first_pool_id = first["PoolId"]
    # Get/Delete's Identifier accepts the pool's name or ARN, not its PoolId (Smithy model:
    # "Valid values include the name and ARN of the media pipeline Kinesis Video Stream
    # pool") -- passing PoolId 404s on both operations every time, not just transiently.
    ctx.on_cleanup(lambda: _delete_pool(chime, pool_name, teardown))

    error = _error_response_with_retry(
        lambda: chime.create_media_pipeline_kinesis_video_stream_pool(
            PoolName=pool_name,
            StreamConfiguration={"Region": ctx.region, "DataRetentionInHours": 4},
        )
    )
    # real AWS rejects a duplicate PoolName with BadRequestException, not ConflictException;
    # the message is checked too since BadRequestException is also used for malformed input
    assert error["Code"] == "BadRequestException", (
        f"expected BadRequestException for duplicate PoolName, got {error['Code']}"
    )
    expected_message = f"Media Pipeline Kinesis Video Stream Pool already exists with {pool_name} name"
    assert error.get("Message") == expected_message, (
        f"expected the BadRequestException message {expected_message!r}, "
        f"got message: {error.get('Message')!r}"
    )

    # effect absent: still exactly one pool with this name, unchanged retention
    matches = [item for item in _list_all_pools(chime) if item["PoolName"] == pool_name]
    assert len(matches) == 1, f"expected exactly one pool named {pool_name!r}, found {len(matches)}"
    assert matches[0]["PoolId"] == first_pool_id, (
        f"expected the listed pool for {pool_name!r} to be the original {first_pool_id}, "
        f"got {matches[0]['PoolId']}"
    )
    unchanged = _get_pool_tolerant(chime, pool_name)
    assert unchanged["StreamConfiguration"]["DataRetentionInHours"] == 2, (
        "expected the rejected duplicate create to leave DataRetentionInHours unchanged at 2, "
        f"got {unchanged['StreamConfiguration']['DataRetentionInHours']}"
    )

    # positive control: a genuinely different name succeeds
    other_name = ctx.unique_name("sim2real-kvsdup-other-")
    second = _create_pool_with_retry(
        ctx,
        chime,
        PoolName=other_name,
        StreamConfiguration={"Region": ctx.region, "DataRetentionInHours": 2},
    )["KinesisVideoStreamPoolConfiguration"]
    second_pool_id = second["PoolId"]
    ctx.on_cleanup(lambda: _delete_pool(chime, other_name, teardown))

    # terminal read is independent of the create call that produced it
    confirmed = _get_pool_tolerant(chime, other_name)
    assert confirmed["PoolId"] == second_pool_id, (
        f"expected an independent read of {other_name!r} to report PoolId={second_pool_id}, "
        f"got {confirmed.get('PoolId')!r}"
    )


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


def _delete_pool(chime, identifier: str, teardown) -> None:
    """Delete the pool, retrying while AWS refuses it with ConflictException."""
    while True:
        try:
            chime.delete_media_pipeline_kinesis_video_stream_pool(Identifier=identifier)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= teardown.deadline():
                raise
        time.sleep(2)


def _ensure_service_linked_role(ctx) -> None:
    """CreateMediaPipelineKinesisVideoStreamPool requires the
    AWSServiceRoleForAmazonChimeSDKMediaPipelines service-linked role to exist in the
    account; create it idempotently (ignore InvalidInputException if it already exists)."""
    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="mediapipelines.chime.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInputException", "InvalidInput"):
            raise


def _create_pool_with_retry(ctx, chime, timeout_s: float = 300.0, interval_s: float = 5.0, **kwargs):
    """The account-level KVS pool quota may be transiently exhausted by concurrent pool
    creations; retry on ResourceLimitExceededException until a slot frees up. A
    just-created AWSServiceRoleForAmazonChimeSDKMediaPipelines service-linked role also
    needs a short propagation window before this operation will accept it; retry the
    specific 'Create a service-linked role' BadRequestException for up to 90s for that
    reason alone."""
    deadline = time.monotonic() + timeout_s
    slr_deadline = time.monotonic() + 90.0
    while True:
        try:
            return chime.create_media_pipeline_kinesis_video_stream_pool(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code == "ResourceLimitExceededException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            if (
                code == "BadRequestException"
                and "service-linked role" in message
                and time.monotonic() < slr_deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _get_pool_tolerant(chime, identifier: str, timeout_s: float = 30.0, interval_s: float = 3.0) -> dict:
    """The most-recently-created pool may not be immediately visible/consistent to Get; poll
    through a short window of NotFoundException before giving up. `identifier` is the pool's
    PoolName (or ARN) -- GetMediaPipelineKinesisVideoStreamPool's Identifier does not accept
    PoolId."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return chime.get_media_pipeline_kinesis_video_stream_pool(Identifier=identifier)[
                "KinesisVideoStreamPoolConfiguration"
            ]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _list_all_pools(chime) -> list:
    out = []
    next_token = None
    while True:
        kwargs = {"NextToken": next_token} if next_token else {}
        resp = chime.list_media_pipeline_kinesis_video_stream_pools(**kwargs)
        out.extend(resp.get("KinesisVideoStreamPools", []))
        next_token = resp.get("NextToken")
        if not next_token:
            return out


def _error_response_with_retry(fn, timeout_s: float = 300.0, interval_s: float = 5.0) -> dict:
    """The account-level KVS pool quota may be transiently exhausted by concurrent pool
    creations; retry on ResourceLimitExceededException until a slot frees up, then
    return the actual rejection {Code, Message} for the duplicate-name attempt. Raises if
    the call unexpectedly succeeds, so a target that accepts the duplicate fails the check."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            error = exc.response["Error"]
            if error["Code"] == "ResourceLimitExceededException" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return error
        else:
            raise AssertionError(
                "expected create_media_pipeline_kinesis_video_stream_pool to be rejected for "
                "the duplicate PoolName, but it succeeded"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
