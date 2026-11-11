"""untag-resource-removes-tag."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "untag-resource-removes-tag"
GROUP = "state"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagResource removes exactly the specified tag keys while leaving other tags intact."""
    chime = ctx.client("chime-sdk-media-pipelines")
    _ensure_service_linked_role(ctx)
    pool_arn, pool_id = _create_active_kvs_pool(ctx, chime)

    chime.tag_resource(
        ResourceARN=pool_arn,
        Tags=[{"Key": "sim2real-remove-me", "Value": "yes"}, {"Key": "sim2real-keep-me", "Value": "yes"}],
    )
    tags_before = {t["Key"]: t["Value"] for t in chime.list_tags_for_resource(ResourceARN=pool_arn)["Tags"]}
    assert "sim2real-remove-me" in tags_before, f"tag_resource did not attach sim2real-remove-me, got {tags_before}"
    assert "sim2real-keep-me" in tags_before, f"tag_resource did not attach sim2real-keep-me, got {tags_before}"

    chime.untag_resource(ResourceARN=pool_arn, TagKeys=["sim2real-remove-me"])

    tags_after = {t["Key"]: t["Value"] for t in chime.list_tags_for_resource(ResourceARN=pool_arn)["Tags"]}
    assert "sim2real-remove-me" not in tags_after, f"untag_resource did not remove sim2real-remove-me, got {tags_after}"
    assert tags_after.get("sim2real-keep-me") == "yes", (
        f"untag_resource altered sim2real-keep-me, expected 'yes' got {tags_after.get('sim2real-keep-me')!r}"
    )


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


def _create_pool_with_retry(ctx, chime, timeout_s: float = 180.0, interval_s: float = 5.0, **kwargs):
    """Retry two transient conditions until the deadline: the account-level KVS pool quota
    may be exhausted by other concurrently running checks (ResourceLimitExceededException), and
    the AWSServiceRoleForAmazonChimeSDKMediaPipelines service-linked role this call depends on is
    subject to IAM propagation lag right after creation, which chime surfaces as a
    BadRequestException naming the service-linked role rather than a distinct error code."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return chime.create_media_pipeline_kinesis_video_stream_pool(**kwargs)
        except ClientError as exc:
            error = exc.response["Error"]
            transient = error["Code"] == "ResourceLimitExceededException" or (
                error["Code"] == "BadRequestException" and "service-linked role" in error.get("Message", "")
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _get_pool_tolerant(chime, pool_arn: str) -> dict:
    """Newly created pools may not be immediately visible to Get (eventual consistency);
    treat a transient NotFoundException right after create as still CREATING. Identifier takes
    the pool's name or ARN, never its opaque PoolId, which Get/Delete never resolve."""
    try:
        return chime.get_media_pipeline_kinesis_video_stream_pool(Identifier=pool_arn)[
            "KinesisVideoStreamPoolConfiguration"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return {"PoolStatus": "CREATING"}
        raise


def _create_active_kvs_pool(ctx, chime):
    pool_name = ctx.unique_name("sim2real-kvspool-")
    created = _create_pool_with_retry(
        ctx,
        chime,
        PoolName=pool_name,
        StreamConfiguration={"Region": ctx.region, "DataRetentionInHours": 2},
    )["KinesisVideoStreamPoolConfiguration"]
    pool_arn = created["PoolArn"]
    pool_id = created["PoolId"]
    ctx.on_cleanup(lambda: chime.delete_media_pipeline_kinesis_video_stream_pool(Identifier=pool_arn))
    final = _poll_until(
        lambda: _get_pool_tolerant(chime, pool_arn),
        lambda cfg: cfg["PoolStatus"] in ("ACTIVE", "FAILED"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert final["PoolStatus"] == "ACTIVE", f"pool never became ACTIVE, ended at {final['PoolStatus']}"
    return pool_arn, pool_id


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
