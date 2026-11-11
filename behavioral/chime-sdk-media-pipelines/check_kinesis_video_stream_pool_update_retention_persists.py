"""kinesis-video-stream-pool-update-retention-persists."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-video-stream-pool-update-retention-persists"
GROUP = "state"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMediaPipelineKinesisVideoStreamPool changes DataRetentionInHours on an ACTIVE
    pool, the pool cycles back to ACTIVE, and the new value is visible on Get."""
    chime = ctx.client("chime-sdk-media-pipelines")
    _ensure_service_linked_role(ctx)
    pool_arn = _create_active_kvs_pool(ctx, chime, retention_hours=2)

    chime.update_media_pipeline_kinesis_video_stream_pool(
        Identifier=pool_arn,
        StreamConfiguration={"DataRetentionInHours": 5},
    )

    final = _poll_until(
        lambda: _get_pool_tolerant(chime, pool_arn),
        lambda cfg: cfg["PoolStatus"] in ("ACTIVE", "FAILED"),
        timeout_s=90.0,
        interval_s=3.0,
    )

    assert final["PoolStatus"] == "ACTIVE", f"pool ended at {final['PoolStatus']} instead of ACTIVE"
    assert final["StreamConfiguration"]["DataRetentionInHours"] == 5, (
        f"expected DataRetentionInHours=5 after update, got "
        f"{final['StreamConfiguration']['DataRetentionInHours']}"
    )


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


def _create_pool_with_retry(ctx, chime, timeout_s: float = 45.0, interval_s: float = 5.0, **kwargs):
    """The account-level KVS pool quota may be transiently exhausted by other concurrently
    running checks (ResourceLimitExceededException); and a service-linked role created in this
    same run needs a few seconds to propagate before Create will honor it (BadRequestException
    naming the service-linked role, observed on real AWS immediately after
    create_service_linked_role). Retry both until they clear."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return chime.create_media_pipeline_kinesis_video_stream_pool(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            retryable = code == "ResourceLimitExceededException" or (
                code == "BadRequestException" and "service-linked role" in message
            )
            if not retryable or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _get_pool_tolerant(chime, identifier: str) -> dict:
    """Newly created pools (or ones just updated) may not be immediately visible/consistent to
    Get (eventual consistency); treat a transient NotFoundException as still in-flight."""
    try:
        return chime.get_media_pipeline_kinesis_video_stream_pool(Identifier=identifier)[
            "KinesisVideoStreamPoolConfiguration"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return {"PoolStatus": "CREATING"}
        raise


def _create_active_kvs_pool(ctx, chime, retention_hours: int = 2):
    pool_name = ctx.unique_name("sim2real-kvspool-")
    created = _create_pool_with_retry(
        ctx,
        chime,
        PoolName=pool_name,
        StreamConfiguration={"Region": ctx.region, "DataRetentionInHours": retention_hours},
        Tags=[{"Key": "sim2real-env", "Value": "test"}, {"Key": "sim2real-owner", "Value": "behavioral"}],
    )["KinesisVideoStreamPoolConfiguration"]
    pool_arn = created["PoolArn"]
    # Get/Update/Delete's Identifier accepts the pool's name or ARN, not its PoolId (Smithy
    # model: "Valid values include the name and ARN of the media pipeline Kinesis Video
    # Stream pool") -- passing PoolId 404s on all three every time, not just transiently.
    ctx.on_cleanup(lambda: chime.delete_media_pipeline_kinesis_video_stream_pool(Identifier=pool_arn))
    final = _poll_until(
        lambda: _get_pool_tolerant(chime, pool_arn),
        lambda cfg: cfg["PoolStatus"] in ("ACTIVE", "FAILED"),
        timeout_s=150.0,
        interval_s=3.0,
    )
    assert final["PoolStatus"] == "ACTIVE", f"pool never became ACTIVE, ended at {final['PoolStatus']}"
    return pool_arn


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

