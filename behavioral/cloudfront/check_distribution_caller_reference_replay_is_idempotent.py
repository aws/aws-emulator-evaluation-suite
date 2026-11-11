"""distribution-caller-reference-replay-is-idempotent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "distribution-caller-reference-replay-is-idempotent"
GROUP = "state-machine"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDistribution replay semantics: resubmitting a byte-identical DistributionConfig
    under an already-used CallerReference returns the SAME distribution rather than creating a
    second one or erroring."""
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-behav-cf-idem-")
    tracked: set[str] = set()

    first = _create_distribution_from_config(ctx, cf, _minimal_distribution_config(ref), tracked)
    dist_id = first["Distribution"]["Id"]

    second = _create_distribution_from_config(ctx, cf, _minimal_distribution_config(ref), tracked)
    replayed_id = second["Distribution"]["Id"]
    assert replayed_id == dist_id, (
        f"identical replay must return the original distribution: {dist_id} vs {replayed_id}"
    )
    assert second["Distribution"]["ARN"] == first["Distribution"]["ARN"], (
        f"replayed create must report the original ARN: "
        f"{first['Distribution']['ARN']!r} vs {second['Distribution']['ARN']!r}"
    )
    assert second["Distribution"]["DomainName"] == first["Distribution"]["DomainName"], (
        f"replayed create must report the original DomainName: "
        f"{first['Distribution']['DomainName']!r} vs {second['Distribution']['DomainName']!r}"
    )

    ids = _collect(
        cf, cf.list_distributions, "ListDistributions", "DistributionList", lambda i: i["Id"]
    )
    assert ids.count(dist_id) == 1, "an idempotent replay must not create a duplicate distribution"


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


def _collect(cf, method, op_name, list_key, extract, **kwargs):
    """Walk a CloudFront Marker/NextMarker paginated list API completely and return
    `extract(item)` for every item, so membership assertions are not silently
    weakened by a truncated first page."""
    out = []
    marker = None
    for _ in range(30):
        call_kwargs = dict(kwargs)
        call_kwargs["MaxItems"] = _max_items(cf, op_name, 100)
        if marker:
            call_kwargs["Marker"] = marker
        resp = method(**call_kwargs)
        listing = resp[list_key]
        for item in listing.get("Items") or []:
            out.append(extract(item))
        if listing.get("NextMarker") and listing.get("IsTruncated", True):
            marker = listing["NextMarker"]
        else:
            break
    return out


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
    enabled: bool = False,
    origin_id: str = "origin1",
    target_origin_id: str | None = None,
) -> dict:
    """A minimal, valid DistributionConfig with one S3-style origin.

    Enabled defaults to False: a disabled distribution still has to reach Deployed before
    DeleteDistribution is accepted, but teardown then skips the extra disable-and-redeploy round
    trip.
    """
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


def _create_distribution_from_config(ctx, cf, config: dict, seen: set | None = None) -> dict:
    """Throttle-tolerant CreateDistribution that registers teardown exactly once per id
    (an idempotent replay returns an id we are already tearing down)."""
    resp = _retrying(
        lambda: cf.create_distribution_with_tags(
            DistributionConfigWithTags={
                "DistributionConfig": config,
                "Tags": {"Items": [{"Key": "sim2real-check", "Value": CHECK}]},
            }
        )
    )
    dist_id = resp["Distribution"]["Id"]
    if seen is None or dist_id not in seen:
        if seen is not None:
            seen.add(dist_id)
        ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    return resp


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
