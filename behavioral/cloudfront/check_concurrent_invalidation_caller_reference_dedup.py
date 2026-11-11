"""concurrent-invalidation-caller-reference-dedup."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-invalidation-caller-reference-dedup"
GROUP = "concurrency"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateInvalidation calls sharing one CallerReference and identical paths
    must collapse to exactly one invalidation Id (no duplicate batches under a race)."""
    cf = ctx.client("cloudfront")
    dist = _create_distribution(ctx, cf, ctx.unique_name("sim2real-behav-cf-inval-race-"))
    dist_id = dist["Distribution"]["Id"]

    ref = ctx.unique_name("sim2real-behav-cf-inval-race-batch-")
    batch = {"Paths": {"Quantity": 1, "Items": ["/race/*"]}, "CallerReference": ref}

    # Seed one invalidation serially so the racers cannot all fail merely because
    # the distribution had not finished its very first deployment.
    seed = _create_invalidation(cf, dist_id, ref, ["/race/*"])
    seed_id = seed["Invalidation"]["Id"]

    def racer():
        return _retrying(
            lambda: cf.create_invalidation(DistributionId=dist_id, InvalidationBatch=batch)
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [pool.submit(racer) for _ in range(8)]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(("ok", future.result()))
            except Exception as exc:  # noqa: BLE001 - racers may legitimately be throttled
                outcomes.append(("err", exc))

    successes = [payload for status, payload in outcomes if status == "ok"]
    assert successes, f"every concurrent CreateInvalidation failed: {outcomes}"

    ids = {r["Invalidation"]["Id"] for r in successes}
    assert ids == {seed_id}, f"expected all racers to dedup onto {seed_id}, got {ids}"

    listed = [
        item["Id"]
        for item in cf.list_invalidations(
            DistributionId=dist_id, MaxItems=_max_items(cf, "ListInvalidations", 100)
        )["InvalidationList"].get("Items")
        or []
    ]
    assert listed.count(seed_id) == 1, listed


_MANAGED_CACHING_OPTIMIZED_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"

_THROTTLE_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
        "SlowDown",
    }
)

_DEPLOY_TIMEOUT_S = 2400
_DEPLOY_INTERVAL_S = 15


def _retrying(fn, attempts: int = 9, base_delay: float = 2.0):
    """Call fn(), retrying with exponential backoff on throttling only."""
    delay = base_delay
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in _THROTTLE_CODES or attempt == attempts - 1:
                raise
            time.sleep(delay)
            delay = min(delay * 2, 30.0)


def _max_items(cf, operation: str, n: int):
    """CloudFront models MaxItems as a string on most list APIs, but not uniformly
    across model versions. Resolve the shape at runtime."""
    try:
        shape = (
            cf.meta.service_model.operation_model(operation).input_shape.members["MaxItems"]
        )
        return str(n) if shape.type_name == "string" else int(n)
    except Exception:
        return str(n)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description} after {timeout_s}s (last: {last!r})")


def _minimal_distribution_config(
    caller_reference: str,
    comment: str = "behavioral-check",
    enabled: bool = True,
    origin_id: str = "origin1",
    target_origin_id: str | None = None,
) -> dict:
    """A minimal, valid DistributionConfig with one S3-style origin."""
    return {
        "CallerReference": caller_reference,
        "Comment": comment,
        "Enabled": enabled,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": f"{caller_reference}.s3.amazonaws.com",
                    "S3OriginConfig": {"OriginAccessIdentity": ""},
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": target_origin_id or origin_id,
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED_POLICY_ID,
        },
    }


def _wait_distribution_deployed(cf, dist_id, timeout_s=_DEPLOY_TIMEOUT_S, interval_s=_DEPLOY_INTERVAL_S):
    return _poll_until(
        lambda: _retrying(lambda: cf.get_distribution(Id=dist_id)),
        lambda resp: resp["Distribution"]["Status"] == "Deployed",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"distribution {dist_id} to reach Deployed",
    )


def _force_delete_distribution(cf, dist_id) -> None:
    """Disable (if needed), wait for Deployed, delete."""
    try:
        cfg_resp = _retrying(lambda: cf.get_distribution_config(Id=dist_id))
        cfg = cfg_resp["DistributionConfig"]
        etag = cfg_resp["ETag"]
        if cfg.get("Enabled"):
            cfg["Enabled"] = False
            etag = _retrying(
                lambda: cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
            )["ETag"]
        _wait_distribution_deployed(cf, dist_id)
        current = _retrying(lambda: cf.get_distribution(Id=dist_id))
        _retrying(lambda: cf.delete_distribution(Id=dist_id, IfMatch=current["ETag"]))
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "EntityNotFound",
            "NoSuchCachePolicy",
            "NoSuchContinuousDeploymentPolicy",
            "NoSuchDistribution",
            "NoSuchFieldLevelEncryptionConfig",
            "NoSuchOrigin",
            "NoSuchOriginRequestPolicy",
            "NoSuchRealtimeLogConfig",
            "NoSuchResponseHeadersPolicy",
            "TrustedKeyGroupDoesNotExist",
            "TrustedSignerDoesNotExist",
        ):
            raise


def _create_distribution(ctx, cf, caller_reference: str, **kwargs) -> dict:
    config = _minimal_distribution_config(caller_reference, **kwargs)
    resp = _retrying(lambda: cf.create_distribution(DistributionConfig=config))
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    return resp


def _create_invalidation(cf, dist_id: str, caller_reference: str, paths: list[str]) -> dict:
    """CreateInvalidation with one retry after a deployment settles."""
    batch = {
        "Paths": {"Quantity": len(paths), "Items": list(paths)},
        "CallerReference": caller_reference,
    }
    try:
        return _retrying(
            lambda: cf.create_invalidation(DistributionId=dist_id, InvalidationBatch=batch)
        )
    except Exception:
        _wait_distribution_deployed(cf, dist_id)
        return _retrying(
            lambda: cf.create_invalidation(DistributionId=dist_id, InvalidationBatch=batch)
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
