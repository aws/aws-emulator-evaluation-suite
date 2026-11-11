"""overly-permissive-invalidation-inconsistent-quantities-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "overly-permissive-invalidation-inconsistent-quantities-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateInvalidation with Paths.Quantity 3 and one Item fails with InconsistentQuantities and its exact message
    and enqueues nothing; a consistent batch right after succeeds and is the only invalidation listed, so the
    refusal is specific to the mismatch."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    cf = ctx.client("cloudfront")
    dist = _create_distribution(ctx, cf, ctx.unique_name("sim2real-behav-cf-invalqty-"), teardown_deadline)
    dist_id = dist["Distribution"]["Id"]

    before = cf.list_invalidations(
        DistributionId=dist_id, MaxItems=_max_items(cf, "ListInvalidations", 100)
    )
    assert (before["InvalidationList"].get("Items") or []) == [], before["InvalidationList"]

    def attempt():
        return _retrying(
            lambda: cf.create_invalidation(
                DistributionId=dist_id,
                InvalidationBatch={
                    # Quantity claims 3 paths but only one is supplied.
                    "Paths": {"Quantity": 3, "Items": ["/only-one/*"]},
                    "CallerReference": ctx.unique_name("sim2real-behav-cf-invalqty-batch-"),
                },
            )
        )

    code, message = _error(attempt)
    assert code == "InconsistentQuantities", code
    expected_message = "The specified quantity of Paths (3) does not match the actual quantity supplied (1)."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the rejected batch enqueued nothing.
    after_reject = cf.list_invalidations(
        DistributionId=dist_id, MaxItems=_max_items(cf, "ListInvalidations", 100)
    )
    assert (after_reject["InvalidationList"].get("Items") or []) == [], after_reject["InvalidationList"]

    # Positive control: the identical distribution accepts a consistent Quantity/Items
    # pair right after, so the rejection above is specific to the mismatch.
    ok = _retrying(
        lambda: cf.create_invalidation(
            DistributionId=dist_id,
            InvalidationBatch={
                "Paths": {"Quantity": 1, "Items": ["/only-one/*"]},
                "CallerReference": ctx.unique_name("sim2real-behav-cf-invalqty-ok-"),
            },
        )
    )
    ok_id = ok["Invalidation"]["Id"]
    assert ok_id, ok

    # Terminal read, independent of both mutating calls: the list now contains exactly
    # the positive control's invalidation -- never one created by the rejected batch.
    final = cf.list_invalidations(
        DistributionId=dist_id, MaxItems=_max_items(cf, "ListInvalidations", 100)
    )
    final_ids = [item["Id"] for item in (final["InvalidationList"].get("Items") or [])]
    assert final_ids == [ok_id], final_ids


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

_DEPLOY_INTERVAL_S = 15

# budget.cleanup_timeout for behavioral/cloudfront, one deadline shared by the teardowns.
_TEARDOWN_RETRY_S = 1800.0


def _error(fn):
    """Call fn(); return its botocore (code, message). A success raises: accepting input AWS refuses
    is a finding in itself, not a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _retrying(fn, attempts: int = 9, base_delay: float = 2.0):
    """Call fn(), retrying with exponential backoff on throttling only.
    Any other ClientError propagates immediately and unchanged, which is what lets
    the rejection assertion above observe the exact service error."""
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


def _wait_distribution_deployed(cf, dist_id, timeout_s, interval_s=_DEPLOY_INTERVAL_S):
    return _poll_until(
        lambda: _retrying(lambda: cf.get_distribution(Id=dist_id)),
        lambda resp: resp["Distribution"]["Status"] == "Deployed",
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"distribution {dist_id} to reach Deployed",
    )


def _force_delete_distribution(cf, dist_id, teardown_deadline) -> None:
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
        deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)
        _wait_distribution_deployed(cf, dist_id, timeout_s=max(0.0, deadline - time.monotonic()))
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


def _create_distribution(ctx, cf, caller_reference: str, teardown_deadline, **kwargs) -> dict:
    config = _minimal_distribution_config(caller_reference, **kwargs)
    resp = _retrying(lambda: cf.create_distribution(DistributionConfig=config))
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id, teardown_deadline))
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
