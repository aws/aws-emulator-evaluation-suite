"""distribution-config-defaults-materialized."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "distribution-config-defaults-materialized"
GROUP = "representation"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A minimal DistributionConfig is echoed back with CloudFront's server-side defaults
    materialized (price class, IPv6, geo restriction, allowed methods, viewer cert)."""
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-behav-cf-defaults-")
    created = _create_distribution(ctx, cf, ref)
    dist_id = created["Distribution"]["Id"]

    # Independent read: assert what GetDistributionConfig reports, not the echo
    # inside the CreateDistribution response.
    cfg = _retrying(lambda: cf.get_distribution_config(Id=dist_id))["DistributionConfig"]

    assert cfg["PriceClass"] == "PriceClass_All", cfg["PriceClass"]
    assert cfg["HttpVersion"] in ("http2", "http2and3"), cfg["HttpVersion"]
    assert cfg["IsIPV6Enabled"] is True
    assert cfg["Aliases"]["Quantity"] == 0
    assert cfg["CacheBehaviors"]["Quantity"] == 0
    assert cfg["CustomErrorResponses"]["Quantity"] == 0
    assert cfg["Logging"]["Enabled"] is False
    assert cfg["Restrictions"]["GeoRestriction"]["RestrictionType"] == "none"
    assert cfg["ViewerCertificate"]["CloudFrontDefaultCertificate"] is True
    assert cfg["WebACLId"] == "", cfg["WebACLId"]
    assert cfg.get("Staging", False) is False

    dcb = cfg["DefaultCacheBehavior"]
    assert dcb["Compress"] is False
    assert dcb["SmoothStreaming"] is False
    assert dcb["AllowedMethods"]["Quantity"] == 2
    assert sorted(dcb["AllowedMethods"]["Items"]) == ["GET", "HEAD"]
    assert dcb["TrustedSigners"]["Enabled"] is False
    assert dcb.get("TrustedKeyGroups", {}).get("Enabled") is False
    assert dcb["FieldLevelEncryptionId"] == ""


# ===== helpers =====

# The AWS-managed "CachingOptimized" cache policy. Referencing a managed policy lets us
# build a minimal, always-valid DefaultCacheBehavior without creating our own.
_MANAGED_CACHING_OPTIMIZED_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"

# CloudFront's control plane is aggressively rate limited. Retry *only* on throttling so
# error-semantics assertions still observe the exact service error they probe for.
_THROTTLE_CODES = frozenset(
    {
        "Throttling",
        "ThrottlingException",
        "RequestLimitExceeded",
        "TooManyRequestsException",
        "SlowDown",
    }
)

# Real CloudFront propagation is measured in minutes, not seconds.
_DEPLOY_TIMEOUT_S = 2400
_DEPLOY_INTERVAL_S = 15


def _retrying(fn, attempts: int = 9, base_delay: float = 2.0):
    """Call fn(), retrying with exponential backoff on throttling only.
    Any other ClientError propagates immediately and unchanged."""
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
    """A minimal, valid DistributionConfig with one S3-style origin and a
    DefaultCacheBehavior that references a managed cache policy (avoiding the
    legacy ForwardedValues shape entirely)."""
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
    """Disable (if needed), wait for Deployed, delete. A distribution can only be
    deleted once it is BOTH disabled and Deployed."""
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


def _create_distribution_from_config(ctx, cf, config: dict) -> dict:
    # Tagged so a tag search (Resource Groups Tagging API, filtered on this
    # exact key/value) finds any remainder if cleanup is ever cut short.
    resp = _retrying(
        lambda: cf.create_distribution_with_tags(
            DistributionConfigWithTags={
                "DistributionConfig": config,
                "Tags": {"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
            }
        )
    )
    dist_id = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _force_delete_distribution(cf, dist_id))
    return resp


def _create_distribution(ctx, cf, caller_reference: str, **kwargs) -> dict:
    return _create_distribution_from_config(
        ctx, cf, _minimal_distribution_config(caller_reference, **kwargs)
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
