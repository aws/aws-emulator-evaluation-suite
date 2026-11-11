"""kinesis-video-stream-pool-creating-to-active-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-video-stream-pool-creating-to-active-transition"
GROUP = "state"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created Kinesis Video Stream pool eventually settles into PoolStatus=ACTIVE,
    and the persisted StreamConfiguration matches what was requested."""
    chime = ctx.client("chime-sdk-media-pipelines")
    _ensure_service_linked_role(ctx)
    pool_name = ctx.unique_name("sim2real-kvspool-")

    created = _create_pool_with_retry(
        ctx,
        chime,
        PoolName=pool_name,
        StreamConfiguration={"Region": ctx.region, "DataRetentionInHours": 3},
        Tags=[{"Key": "sim2real-env", "Value": "test"}, {"Key": "sim2real-owner", "Value": "behavioral"}],
    )["KinesisVideoStreamPoolConfiguration"]
    pool_arn = created["PoolArn"]
    ctx.on_cleanup(lambda: chime.delete_media_pipeline_kinesis_video_stream_pool(Identifier=pool_arn))

    assert created["PoolStatus"] in ("CREATING", "ACTIVE"), (
        f"expected CREATING or ACTIVE right after create, got {created['PoolStatus']!r}"
    )

    final = _poll_until(
        lambda: _get_pool_tolerant(chime, pool_arn),
        lambda cfg: cfg["PoolStatus"] in ("ACTIVE", "FAILED"),
        timeout_s=250.0,
        interval_s=5.0,
    )

    assert final["PoolStatus"] == "ACTIVE", f"pool ended at {final['PoolStatus']} instead of ACTIVE"
    assert final["StreamConfiguration"]["Region"] == ctx.region, (
        f"expected Region={ctx.region!r}, got {final['StreamConfiguration']['Region']!r}"
    )
    assert final["StreamConfiguration"]["DataRetentionInHours"] == 3, (
        f"expected DataRetentionInHours=3, got {final['StreamConfiguration']['DataRetentionInHours']!r}"
    )
    assert final["PoolName"] == pool_name, f"expected PoolName={pool_name!r}, got {final['PoolName']!r}"


def _ensure_service_linked_role(ctx) -> None:
    """CreateMediaPipelineKinesisVideoStreamPool requires the
    AWSServiceRoleForAmazonChimeSDKMediaPipelines service-linked role to exist in the
    account; create it idempotently (ignore InvalidInputException if it already exists)."""
    from botocore.exceptions import ClientError as _CE

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="mediapipelines.chime.amazonaws.com")
    except _CE as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInputException", "InvalidInput"):
            raise


def _create_pool_with_retry(ctx, chime, timeout_s: float = 300.0, interval_s: float = 5.0, **kwargs):
    """Retries two transient conditions until a slot frees up: the account-level KVS pool
    quota, which other concurrently running checks may exhaust; and the freshly-created
    AWSServiceRoleForAmazonChimeSDKMediaPipelines service-linked role, which IAM propagates
    asynchronously, so a create issued right after it can still be refused for a few seconds."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return chime.create_media_pipeline_kinesis_video_stream_pool(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            retryable = code == "ResourceLimitExceededException" or (
                code == "BadRequestException" and "service-linked role" in message.lower()
            )
            if not retryable or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _get_pool_tolerant(chime, pool_arn: str) -> dict:
    """Newly created pools may not be immediately visible to Get (eventual consistency);
    treat a transient NotFoundException right after create as still CREATING."""
    from botocore.exceptions import ClientError as _CE

    try:
        return chime.get_media_pipeline_kinesis_video_stream_pool(Identifier=pool_arn)[
            "KinesisVideoStreamPoolConfiguration"
        ]
    except _CE as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return {"PoolStatus": "CREATING"}
        raise


def _poll_until(probe, predicate, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
