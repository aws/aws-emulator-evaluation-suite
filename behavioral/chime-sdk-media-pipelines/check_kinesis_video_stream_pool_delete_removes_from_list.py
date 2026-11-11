"""kinesis-video-stream-pool-delete-removes-from-list."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "kinesis-video-stream-pool-delete-removes-from-list"
GROUP = "state"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteMediaPipelineKinesisVideoStreamPool removes the pool: Get eventually returns
    NotFoundException and the pool disappears from ListMediaPipelineKinesisVideoStreamPools."""
    chime = ctx.client("chime-sdk-media-pipelines")
    _ensure_service_linked_role(ctx)
    pool_arn, pool_name = _create_kvs_pool(ctx, chime)

    _delete_pool_with_retry(chime, pool_arn, timeout_s=60.0, interval_s=3.0)

    gone = _await_client_error(
        lambda: chime.get_media_pipeline_kinesis_video_stream_pool(Identifier=pool_arn),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert gone["Code"] == "NotFoundException", f"expected Get to report NotFoundException after delete, got {gone!r}"
    assert gone["Message"] == "Unable to find the requested identifier", (
        f"unexpected NotFoundException message on Get after delete: {gone['Message']!r}"
    )

    names_in_list = {item["PoolName"] for item in _list_all_pools(chime)}
    assert pool_name not in names_in_list, f"deleted pool {pool_name!r} still present in ListMediaPipelineKinesisVideoStreamPools"


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
    """Retry on two transient conditions: the account-level KVS pool quota may be
    momentarily exhausted by other concurrently running checks (ResourceLimitExceededException),
    and a service-linked role just created by _ensure_service_linked_role may not yet have
    propagated to the pipelines control plane, which reports that as a BadRequestException
    naming the role."""
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


def _create_kvs_pool(ctx, chime):
    """This check's own contract is "delete removes the pool", which real AWS honours regardless of
    the pool's current PoolStatus, so no wait for ACTIVE belongs here."""
    pool_name = ctx.unique_name("sim2real-kvspool-")
    created = _create_pool_with_retry(
        ctx,
        chime,
        PoolName=pool_name,
        StreamConfiguration={"Region": ctx.region, "DataRetentionInHours": 2},
        Tags=[{"Key": "sim2real", "Value": "audit"}],
    )["KinesisVideoStreamPoolConfiguration"]
    pool_arn = created["PoolArn"]
    ctx.on_cleanup(lambda: _delete_pool_tolerant(chime, pool_arn))
    return pool_arn, pool_name


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


def _delete_pool_with_retry(chime, identifier: str, timeout_s: float, interval_s: float) -> None:
    """A pool ARN returned by Create may not be immediately visible to Delete (eventual
    consistency); retry on NotFoundException until it resolves or the deadline expires, at
    which point a genuine NotFoundException is the real answer."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            chime.delete_media_pipeline_kinesis_video_stream_pool(Identifier=identifier)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _delete_pool_tolerant(chime, identifier: str) -> None:
    """Cleanup safety net: the check's own body already deletes the pool it created, so a
    second delete here is expected to see NotFoundException whenever the body ran to
    completion; only re-raise on anything else."""
    try:
        chime.delete_media_pipeline_kinesis_video_stream_pool(Identifier=identifier)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _await_client_error(fn, timeout_s: float, interval_s: float) -> dict:
    """Call fn() until it raises; return its botocore Error dict. A read that keeps
    SUCCEEDING past the deadline raises, so a pool that outlives its delete fails loudly."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            return exc.response["Error"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"Get still succeeds {timeout_s}s after delete: {result!r}")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
