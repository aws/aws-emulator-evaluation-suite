"""distribution-cache-behaviors-quantity-mismatch-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_MANAGED_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

CHECK = "distribution-cache-behaviors-quantity-mismatch-rejected"
GROUP = "cache-behaviors"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDistribution rejects a CacheBehaviors.Quantity that does not match the submitted
    Items count with InconsistentQuantities and creates no distribution; the same config with a
    matching Quantity succeeds."""
    cf = ctx.client("cloudfront")
    origin_id = "primary-origin"
    domain = f"{ctx.unique_name('sim2real-behav-origin-')}.example.com"
    comment = ctx.unique_name("sim2real-behav-cf-mismatch-")

    def _base_config(caller_reference):
        return {
            "CallerReference": caller_reference,
            "Comment": comment,
            "Enabled": False,
            "Origins": {
                "Quantity": 1,
                "Items": [
                    {
                        "Id": origin_id,
                        "DomainName": domain,
                        "CustomOriginConfig": {
                            "HTTPPort": 80,
                            "HTTPSPort": 443,
                            "OriginProtocolPolicy": "https-only",
                            "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                            "OriginReadTimeout": 30,
                            "OriginKeepaliveTimeout": 5,
                        },
                    }
                ],
            },
            "DefaultCacheBehavior": {
                "TargetOriginId": origin_id,
                "ViewerProtocolPolicy": "redirect-to-https",
                "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
            },
        }

    def _behavior(pattern):
        return {
            "PathPattern": pattern,
            "TargetOriginId": origin_id,
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": _MANAGED_CACHING_OPTIMIZED,
        }

    bad_cfg = _base_config(ctx.unique_name("sim2real-behav-cf-bad-"))
    bad_cfg["CacheBehaviors"] = {"Quantity": 2, "Items": [_behavior("/one/*")]}

    code, message = _error(lambda: cf.create_distribution(DistributionConfig=bad_cfg))
    assert code == "InconsistentQuantities", f"expected InconsistentQuantities, got {code!r}"
    assert message == (
        "The specified quantity of CacheBehaviors (2) does not match the actual quantity supplied (1)."
    ), f"unexpected InconsistentQuantities message: {message!r}"

    # effect absent: no distribution exists carrying this run's unique comment
    assert not _distribution_ids_with_comment(cf, comment), (
        f"a rejected CreateDistribution must create nothing, but found a distribution tagged {comment!r}"
    )

    # positive control: the same shape with a matching Quantity succeeds
    good_cfg = _base_config(ctx.unique_name("sim2real-behav-cf-good-"))
    good_cfg["CacheBehaviors"] = {"Quantity": 1, "Items": [_behavior("/one/*")]}
    created = cf.create_distribution(DistributionConfig=good_cfg)
    dist_id = created["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _cleanup_distribution(cf, dist_id))
    created_behaviors = created["Distribution"]["DistributionConfig"]["CacheBehaviors"]
    assert created_behaviors["Quantity"] == 1, created_behaviors["Quantity"]
    assert created_behaviors["Items"][0]["PathPattern"] == "/one/*", created_behaviors["Items"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _distribution_ids_with_comment(cf, comment):
    found = []
    for page in cf.get_paginator("list_distributions").paginate():
        for item in page["DistributionList"].get("Items", []) or []:
            if item.get("Comment") == comment:
                found.append(item["Id"])
    return found


def _wait_distribution_deployed(cf, dist_id, timeout_s=1500, interval_s=20):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.get_distribution(Id=dist_id)["Distribution"]["Status"]
        if status == "Deployed":
            return status
        time.sleep(interval_s)
    raise AssertionError(f"distribution {dist_id} did not reach Deployed within {timeout_s}s (last={status})")


def _cleanup_distribution(cf, dist_id):
    try:
        current = cf.get_distribution_config(Id=dist_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise
    cfg = current["DistributionConfig"]
    etag = current["ETag"]
    if cfg.get("Enabled"):
        cfg["Enabled"] = False
        updated = cf.update_distribution(Id=dist_id, IfMatch=etag, DistributionConfig=cfg)
        etag = updated["ETag"]
    _wait_distribution_deployed(cf, dist_id)
    etag = cf.get_distribution_config(Id=dist_id)["ETag"]
    try:
        cf.delete_distribution(Id=dist_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchDistribution":
            return
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
