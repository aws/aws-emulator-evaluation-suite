"""op-contract-createInvalidation."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createInvalidation"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateInvalidation echoes the submitted batch and starts InProgress; unknown dist id is rejected."""
    cf = ctx.client("cloudfront")
    dist = _create_minimal_distribution(ctx)

    caller_ref = ctx.unique_name("sim2real-inval-")
    resp = cf.create_invalidation(
        DistributionId=dist["id"],
        InvalidationBatch={
            "CallerReference": caller_ref,
            "Paths": {"Quantity": 2, "Items": ["/*", "/index.html"]},
        },
    )
    invalidation = resp["Invalidation"]
    assert invalidation["Id"], "expected CreateInvalidation to return a non-empty Id"
    assert invalidation["Status"] in ("InProgress", "Completed"), invalidation["Status"]
    batch = invalidation["InvalidationBatch"]
    assert batch["CallerReference"] == caller_ref, (
        f"expected CallerReference {caller_ref!r}, got {batch['CallerReference']!r}"
    )
    assert sorted(batch["Paths"]["Items"]) == ["/*", "/index.html"], (
        f"expected echoed paths ['/*', '/index.html'], got {sorted(batch['Paths']['Items'])!r}"
    )
    assert resp.get("Location"), "expected a Location header value"

    # It should be independently retrievable via GetInvalidation.
    fetched = cf.get_invalidation(DistributionId=dist["id"], Id=invalidation["Id"])["Invalidation"]
    assert fetched["Id"] == invalidation["Id"], (
        f"expected GetInvalidation to return Id {invalidation['Id']!r}, got {fetched['Id']!r}"
    )

    # Distinct error boundary: an invalidation against a distribution id that doesn't exist.
    code, message = _error(
        lambda: cf.create_invalidation(
            DistributionId="EDFAKEDOESNOTEXIST1",
            InvalidationBatch={
                "CallerReference": ctx.unique_name("sim2real-inval-missing-"),
                "Paths": {"Quantity": 1, "Items": ["/*"]},
            },
        )
    )
    assert code == "NoSuchDistribution", f"expected NoSuchDistribution, got {code}"
    expected = "The specified distribution does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _create_minimal_distribution(ctx) -> dict:
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-dist-")
    origin_domain = f"{ctx.unique_name('origin')}.example.com"
    config = {
        "CallerReference": ref,
        "Comment": "sim2real behavioral check",
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": "origin1",
                    "DomainName": origin_domain,
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "http-only",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "origin1",
            "ViewerProtocolPolicy": "allow-all",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
        },
    }
    resp = cf.create_distribution_with_tags(
        DistributionConfigWithTags={
            "DistributionConfig": config,
            "Tags": {"Items": [{"Key": "sim2real-owner", "Value": "behavioral-check"}]},
        }
    )
    dist = resp["Distribution"]
    dist_id = dist["Id"]
    ctx.on_cleanup(lambda: _cleanup_distribution(ctx, dist_id))
    return {"id": dist_id, "arn": dist["ARN"], "etag": resp["ETag"]}


def _cleanup_distribution(ctx, dist_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        cfg_resp = cf.get_distribution_config(Id=dist_id)
        etag = cfg_resp["ETag"]
        dist_config = cfg_resp["DistributionConfig"]
        if dist_config.get("Enabled"):
            dist_config["Enabled"] = False
            etag = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=dist_config)["ETag"]
        deadline = time.monotonic() + 180
        status = None
        while time.monotonic() < deadline:
            info = cf.get_distribution(Id=dist_id)
            status = info["Distribution"]["Status"]
            etag = info["ETag"]
            if status == "Deployed":
                break
            time.sleep(10)
        if status == "Deployed":
            cf.delete_distribution(Id=dist_id, IfMatch=etag)
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
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
