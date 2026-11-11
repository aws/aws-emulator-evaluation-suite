"""op-contract-get-invalidation."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-get-invalidation"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetInvalidation reflects the invalidation batch just created and 404s on an unknown invalidation Id."""
    cf = ctx.client("cloudfront")
    dist_id, _etag = _create_minimal_distribution(ctx)
    ctx.on_cleanup(lambda: _cleanup_distribution_best_effort(ctx, dist_id))

    paths = ["/sim2real-behavioral-check/*"]
    inv_resp = cf.create_invalidation(
        DistributionId=dist_id,
        InvalidationBatch={
            "Paths": {"Quantity": len(paths), "Items": paths},
            "CallerReference": ctx.unique_name("sim2real-inv-ref-"),
        },
    )
    inv_id = inv_resp["Invalidation"]["Id"]

    # success path
    got = cf.get_invalidation(DistributionId=dist_id, Id=inv_id)
    invalidation = got["Invalidation"]
    assert invalidation["Status"] in ("InProgress", "Completed"), invalidation["Status"]
    assert invalidation["InvalidationBatch"]["Paths"]["Items"] == paths, (
        f"expected paths {paths}, got {invalidation['InvalidationBatch']['Paths']['Items']}"
    )
    create_time = invalidation["CreateTime"]
    assert isinstance(create_time, datetime), f"expected a datetime CreateTime, got {create_time!r}"
    age_s = (datetime.now(timezone.utc) - create_time).total_seconds()
    assert -60 <= age_s <= 300, f"expected CreateTime within the last few minutes, was {age_s}s old"

    # error boundary: unknown invalidation Id on a real distribution
    err, message = _error(lambda: cf.get_invalidation(DistributionId=dist_id, Id="IBOGUS0000000000"))
    assert err == "NoSuchInvalidation", f"expected NoSuchInvalidation, got {err}"
    assert message == "The specified invalidation does not exist.", (
        f"expected AWS's exact message, got {message!r}"
    )


def _minimal_distribution_config(ctx, comment: str) -> dict[str, Any]:
    return {
        "CallerReference": ctx.unique_name("sim2real-cf-"),
        "Comment": comment,
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": f"{ctx.unique_name('origin')}.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "https-only",
                        "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_DISABLED_POLICY_ID,
        },
    }


def _create_minimal_distribution(ctx) -> tuple[str, str]:
    cf = ctx.client("cloudfront")
    resp = cf.create_distribution(DistributionConfig=_minimal_distribution_config(ctx, "sim2real behavioral check"))
    return resp["Distribution"]["Id"], resp["ETag"]


def _cleanup_distribution_best_effort(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        etag = cfg_resp["ETag"]
        config = cfg_resp["DistributionConfig"]
        if config.get("Enabled"):
            config["Enabled"] = False
            etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=config)["ETag"]
        deadline = time.monotonic() + 240
        while time.monotonic() < deadline:
            desc = cf.get_distribution(Id=dist_id)
            etag = desc["ETag"]
            if desc["Distribution"]["Status"] == "Deployed":
                cf.delete_distribution(Id=dist_id, IfMatch=etag)
                return
            time.sleep(10)
        # best effort only: distribution left disabled if it never reached Deployed in time
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


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
