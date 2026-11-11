"""tag-resource-and-list-tags-roundtrip."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-and-list-tags-roundtrip"
GROUP = "state"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource on an ACTIVE Kinesis Video Stream pool attaches two tags, and
    ListTagsForResource returns both with their values."""
    chime = ctx.client("chime-sdk-media-pipelines")
    _ensure_service_linked_role(ctx)
    pool_arn = _create_active_kvs_pool(ctx, chime, _Teardown())

    chime.tag_resource(
        ResourceARN=pool_arn,
        Tags=[{"Key": "sim2real-env", "Value": "test"}, {"Key": "sim2real-owner", "Value": "behavioral"}],
    )

    tags = {t["Key"]: t["Value"] for t in chime.list_tags_for_resource(ResourceARN=pool_arn)["Tags"]}
    assert tags.get("sim2real-env") == "test"
    assert tags.get("sim2real-owner") == "behavioral"


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
    from botocore.exceptions import ClientError as _CE

    iam = ctx.client("iam")
    try:
        iam.create_service_linked_role(AWSServiceName="mediapipelines.chime.amazonaws.com")
    except _CE as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInputException", "InvalidInput"):
            raise


def _create_pool_with_retry(ctx, chime, timeout_s: float = 300.0, interval_s: float = 5.0, **kwargs):
    """The account-level KVS pool quota may be transiently exhausted by concurrent pool
    creations; retry on ResourceLimitExceededException until a slot frees up."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return chime.create_media_pipeline_kinesis_video_stream_pool(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceLimitExceededException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _get_pool_tolerant(chime, identifier: str) -> dict:
    """Newly created pools may not be immediately visible to Get (eventual consistency);
    treat a transient NotFoundException right after create as still CREATING. Get's
    Identifier takes the pool's name or ARN, not its PoolId."""
    try:
        return chime.get_media_pipeline_kinesis_video_stream_pool(Identifier=identifier)[
            "KinesisVideoStreamPoolConfiguration"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return {"PoolStatus": "CREATING"}
        raise


def _create_active_kvs_pool(ctx, chime, teardown):
    pool_name = ctx.unique_name("sim2real-kvspool-")
    created = _create_pool_with_retry(
        ctx,
        chime,
        timeout_s=45.0,
        PoolName=pool_name,
        StreamConfiguration={"Region": ctx.region, "DataRetentionInHours": 2},
    )["KinesisVideoStreamPoolConfiguration"]
    pool_arn = created["PoolArn"]
    ctx.on_cleanup(lambda: _delete_pool(chime, pool_arn, teardown))
    final = _poll_until(
        lambda: _get_pool_tolerant(chime, pool_arn),
        lambda cfg: cfg["PoolStatus"] in ("ACTIVE", "FAILED"),
        timeout_s=230.0,
        interval_s=5.0,
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
