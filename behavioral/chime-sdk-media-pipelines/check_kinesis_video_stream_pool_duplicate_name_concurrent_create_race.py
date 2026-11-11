"""kinesis-video-stream-pool-duplicate-name-concurrent-create-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-video-stream-pool-duplicate-name-concurrent-create-race"
GROUP = "concurrency"
SERVICES = ["chime-sdk-media-pipelines"]

_SLR_MESSAGE_PREFIX = "Create a service-linked role"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N racers calling CreateMediaPipelineKinesisVideoStreamPool with one PoolName yield exactly
    one pool; every other racer gets BadRequestException, either the exact duplicate-name message
    or, while the winner is still being created, a message naming the winner's internal id."""
    chime = ctx.client("chime-sdk-media-pipelines")
    _ensure_service_linked_role(ctx)
    pool_name = ctx.unique_name("sim2real-kvsrace-")
    racer_count = 5

    retry_s = 120.0
    left = ctx.time_left()
    if left is not None:
        retry_s = max(1.0, min(retry_s, left - 45.0))
    _await_service_linked_role(ctx, chime, retry_s)

    def _attempt(i: int):
        deadline = time.monotonic() + retry_s
        while True:
            try:
                resp = chime.create_media_pipeline_kinesis_video_stream_pool(
                    PoolName=pool_name,
                    StreamConfiguration={"Region": ctx.region, "DataRetentionInHours": 2},
                    ClientRequestToken=f"{pool_name}-token-{i}",
                    Tags=[{"Key": "sim2real-env", "Value": "test"}],
                )
                cfg = resp["KinesisVideoStreamPoolConfiguration"]
                return ("ok", cfg["PoolId"], cfg["PoolArn"])
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceLimitExceededException" and time.monotonic() < deadline:
                    time.sleep(5.0)
                    continue
                return ("error", code, exc.response["Error"].get("Message", ""))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(_attempt, range(racer_count)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    # Get/Delete accept the pool's name or ARN, not its PoolId.
    for _, _, pool_arn in successes:
        ctx.on_cleanup(lambda _arn=pool_arn: _delete_pool(chime, _arn))

    assert len(successes) == 1, f"expected exactly 1 winner, got {len(successes)}: {results}"
    assert len(failures) == racer_count - 1, (
        f"expected {racer_count - 1} losers, got {len(failures)}: {results}"
    )
    winner_pool_id = successes[0][1]

    assert all(code == "BadRequestException" for _, code, _ in failures), (
        f"expected every loser to get BadRequestException, got: {failures}"
    )
    # A loser arriving after the winner exists gets the duplicate-name message; one overlapping
    # the winner's creation gets a message naming the winner's internal id, the trailing UUID
    # segment of its PoolId ("ChimeMediaPipelines-<slug>-<uuid>").
    duplicate_message = (
        f"Media Pipeline Kinesis Video Stream Pool already exists with {pool_name} name"
    )
    winner_uuid = winner_pool_id[-36:]
    overlap_message = (
        f"A resource with the same resourceName but a different internalId already exists: "
        f"{winner_uuid}"
    )
    for _, _, msg in failures:
        expected = duplicate_message if msg.startswith("Media Pipeline") else overlap_message
        assert msg == expected, (
            f"expected a loser's message to be {duplicate_message!r} or {overlap_message!r}, "
            f"got: {msg!r}"
        )

    # Confirm exactly one pool with this name actually exists (no partial double-create).
    # Poll briefly: the winning create may not be immediately reflected in List (eventual
    # consistency) right after the race resolves.
    matches = _poll_until(
        lambda: [item for item in _list_all_pools(chime) if item["PoolName"] == pool_name],
        lambda found: len(found) >= 1,
        timeout_s=_cap(ctx, 30.0),
        interval_s=3.0,
        description=f"pool {pool_name!r} to appear in ListMediaPipelineKinesisVideoStreamPools",
    )
    assert len(matches) == 1, f"expected exactly 1 pool named {pool_name!r}, found: {matches}"
    assert matches[0]["PoolId"] == winner_pool_id, (
        f"expected the listed pool to be the race winner {winner_pool_id!r}, got {matches[0]['PoolId']!r}"
    )


def _cap(ctx, own_s: float, margin_s: float = 15.0) -> float:
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _delete_pool(chime, identifier: str) -> None:
    try:
        chime.delete_media_pipeline_kinesis_video_stream_pool(Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until(probe, predicate, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"timed out after {timeout_s}s waiting for {description}; last observed: {value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


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


def _await_service_linked_role(ctx, chime, timeout_s: float) -> None:
    """Create and delete a throwaway pool until the service-linked role is in effect."""
    name = ctx.unique_name("sim2real-kvswarm-")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            arn = chime.create_media_pipeline_kinesis_video_stream_pool(
                PoolName=name,
                StreamConfiguration={"Region": ctx.region, "DataRetentionInHours": 2},
                Tags=[{"Key": "sim2real-env", "Value": "test"}],
            )["KinesisVideoStreamPoolConfiguration"]["PoolArn"]
        except ClientError as exc:
            err = exc.response["Error"]
            if (
                err["Code"] == "BadRequestException"
                and err.get("Message", "").startswith(_SLR_MESSAGE_PREFIX)
                and time.monotonic() < deadline
            ):
                time.sleep(5.0)
                continue
            raise
        ctx.on_cleanup(lambda _arn=arn: _delete_pool(chime, _arn))
        _delete_pool(chime, arn)
        return


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
