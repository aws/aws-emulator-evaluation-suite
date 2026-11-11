"""create-media-pipeline-kinesis-video-stream-pool-missing-permission-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-media-pipeline-kinesis-video-stream-pool-missing-permission-rejected"
GROUP = "overly-permissive"
SERVICES = ["chime-sdk-media-pipelines"]


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A caller assuming an IAM role with NO attached permissions gets denied when calling
    CreateMediaPipelineKinesisVideoStreamPool; no pool is created under that attempt, and the
    same call with properly-permissioned credentials still succeeds (positive control)."""
    chime = ctx.client("chime-sdk-media-pipelines")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    _ensure_service_linked_role(ctx, iam)

    role_name = ctx.unique_name("sim2real-nopolicy-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    creds = _assume_role_with_retry(sts, role_arn, timeout_s=60.0, interval_s=3.0)

    restricted_client = ctx.client(
        "chime-sdk-media-pipelines",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )

    pool_name = ctx.unique_name("sim2real-kvsdenied-")
    ctx.on_cleanup(lambda: _delete_pool_by_name_if_present(chime, pool_name))
    error = _client_error(
        lambda: _create_with_fresh_creds_retry(restricted_client, ctx, pool_name)
    )
    assert error["Code"] == "AccessDeniedException", (
        f"expected AccessDeniedException for a caller with no attached policy, got {error!r}"
    )
    action = "chime:CreateMediaPipelineKinesisVideoStreamPool"
    expected_message = (
        f"User: arn:aws:sts::{account_id}:assumed-role/{role_name}/sim2real-denied-session "
        f"is not authorized to perform: {action} on resource: "
        f"arn:aws:chime:{ctx.region}:{account_id}:media-pipeline-kinesis-video-stream-pool/* "
        f"because no identity-based policy allows the {action} action"
    )
    assert error["Message"] == expected_message, (
        f"expected message {expected_message!r}, got {error['Message']!r}"
    )

    # effect absent: no pool with that name exists
    matches = [item for item in _list_all_pools(chime) if item["PoolName"] == pool_name]
    assert matches == [], f"expected no pool named {pool_name!r} after the denied call, found {matches!r}"

    # positive control: the properly-permissioned caller can create it
    created = _create_pool_with_retry(
        ctx,
        chime,
        PoolName=pool_name,
        StreamConfiguration={"Region": ctx.region, "DataRetentionInHours": 2},
    )["KinesisVideoStreamPoolConfiguration"]
    pool_id = created["PoolId"]
    pool_arn = created["PoolArn"]
    ctx.on_cleanup(
        lambda: chime.delete_media_pipeline_kinesis_video_stream_pool(Identifier=pool_arn)
    )

    # terminal assertion: an independent List, not an echo of the Create response
    found = _await_pool_in_list(chime, pool_id, timeout_s=90.0, interval_s=3.0)
    assert found["PoolName"] == pool_name, (
        f"expected the positive-control pool to be visible in List as {pool_name!r}, got {found['PoolName']!r}"
    )


def _ensure_service_linked_role(ctx, iam) -> None:
    """CreateMediaPipelineKinesisVideoStreamPool requires the
    AWSServiceRoleForAmazonChimeSDKMediaPipelines service-linked role to exist in the
    account; create it idempotently (ignore InvalidInputException if it already exists)."""
    try:
        iam.create_service_linked_role(AWSServiceName="mediapipelines.chime.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidInputException", "InvalidInput"):
            raise


def _create_pool_with_retry(ctx, chime, timeout_s: float = 300.0, interval_s: float = 5.0, **kwargs):
    """The account-level KVS pool quota may be transiently exhausted by other concurrently
    running checks; retry on ResourceLimitExceededException until a slot frees up. Also retry
    the BadRequestException real AWS returns for a few seconds right after
    AWSServiceRoleForAmazonChimeSDKMediaPipelines is created (the service-linked role is
    visible in IAM before this control plane recognizes it)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return chime.create_media_pipeline_kinesis_video_stream_pool(**kwargs)
        except ClientError as exc:
            error = exc.response["Error"]
            retryable = error["Code"] == "ResourceLimitExceededException" or (
                error["Code"] == "BadRequestException"
                and "service-linked role" in error.get("Message", "")
            )
            if not retryable or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _assume_role_with_retry(sts, role_arn: str, timeout_s: float, interval_s: float) -> dict:
    """Newly created IAM role trust policies are eventually consistent; retry the actual
    AssumeRole call (not a bare sleep) until it succeeds or the timeout expires."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName="sim2real-denied-session")[
                "Credentials"
            ]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDenied", "AccessDeniedException") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _await_pool_in_list(chime, pool_id: str, timeout_s: float, interval_s: float) -> dict:
    """A freshly created pool may not be immediately visible on List (eventual consistency);
    poll the same independent read the effect-absent leg above already uses, bounded by a
    deadline, until this specific pool id appears."""
    deadline = time.monotonic() + timeout_s
    seen = []
    while True:
        seen = _list_all_pools(chime)
        for item in seen:
            if item["PoolId"] == pool_id:
                return item
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"pool {pool_id!r} never appeared in List within {timeout_s}s; "
                f"last saw {len(seen)} pool(s): {[i['PoolId'] for i in seen]!r}"
            )
        time.sleep(interval_s)


def _create_with_fresh_creds_retry(restricted_client, ctx, pool_name: str, timeout_s: float = 30.0, interval_s: float = 3.0):
    """Freshly assumed credentials can take a few seconds to propagate to a service's own
    signing verification, independently of the AssumeRole trust-policy propagation already
    handled above; retry the specific token-not-yet-recognized codes, never the eventual
    AccessDeniedException itself."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return restricted_client.create_media_pipeline_kinesis_video_stream_pool(
                PoolName=pool_name,
                StreamConfiguration={"Region": ctx.region, "DataRetentionInHours": 2},
            )
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("UnrecognizedClientException", "InvalidClientTokenId") or time.monotonic() >= deadline:
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


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(
        f"expected AccessDeniedException, but the call SUCCEEDED and returned {result!r}"
    )


def _delete_pool_by_name_if_present(chime, pool_name: str) -> None:
    """Safety net for an over-permissive target: if the denied call above unexpectedly
    created a pool, find it by name (we never got its id) and remove it. The positive control
    shares the name and is deleted first, so a not-found on a still-listed pool is tolerated."""
    for item in _list_all_pools(chime):
        if item["PoolName"] == pool_name:
            try:
                chime.delete_media_pipeline_kinesis_video_stream_pool(Identifier=item["PoolArn"])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NotFoundException":
                    raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
