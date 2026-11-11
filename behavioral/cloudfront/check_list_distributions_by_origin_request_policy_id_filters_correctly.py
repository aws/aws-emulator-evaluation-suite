"""list-distributions-by-origin-request-policy-id-filters-correctly."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-distributions-by-origin-request-policy-id-filters-correctly"
GROUP = "server-side"
SERVICES = ["cloudfront"]

_MANAGED_CACHING_DISABLED_POLICY_ID = "4135ea2d-6df8-44a3-9df3-4b5a84be39ad"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDistributionsByOriginRequestPolicyId returns only the distribution whose default
    cache behavior attaches a given origin request policy, not an unrelated control
    distribution without it."""
    cf = ctx.client("cloudfront")

    policy_ref = ctx.unique_name("sim2real-orp-")
    policy = cf.create_origin_request_policy(
        OriginRequestPolicyConfig={
            "Name": policy_ref,
            "Comment": "sim2real-behav cloudfront check",
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        }
    )["OriginRequestPolicy"]
    policy_id = policy["Id"]
    ctx.on_cleanup(
        lambda: cf.delete_origin_request_policy(Id=policy_id, IfMatch=_current_orp_etag(cf, policy_id))
    )

    wired_id = _create_distribution(
        ctx, cf, ctx.unique_name("sim2real-orp-wired-"), OriginRequestPolicyId=policy_id
    )
    control_id = _create_distribution(ctx, cf, ctx.unique_name("sim2real-orp-ctrl-"))

    resp = cf.list_distributions_by_origin_request_policy_id(OriginRequestPolicyId=policy_id)
    ids = set(resp["DistributionIdList"].get("Items", []))
    assert wired_id in ids, f"expected wired distribution {wired_id} in {ids}"
    assert control_id not in ids, f"control distribution {control_id} unexpectedly in {ids}"


def _current_orp_etag(cf, policy_id: str) -> str:
    return cf.get_origin_request_policy(Id=policy_id)["ETag"]


def _create_distribution(ctx, cf, ref: str, **default_cache_behavior_overrides) -> str:
    ref = ref.lower()
    origin_id = "origin1"
    default_cache_behavior = {
        "TargetOriginId": origin_id,
        "ViewerProtocolPolicy": "allow-all",
        "CachePolicyId": _MANAGED_CACHING_DISABLED_POLICY_ID,
    }
    default_cache_behavior.update(default_cache_behavior_overrides)
    config = {
        "CallerReference": ref,
        "Comment": "sim2real-behav cloudfront check",
        "Enabled": False,
        "Origins": {
            "Quantity": 1,
            "Items": [
                {
                    "Id": origin_id,
                    "DomainName": f"{ref}.example.com",
                    "CustomOriginConfig": {
                        "HTTPPort": 80,
                        "HTTPSPort": 443,
                        "OriginProtocolPolicy": "match-viewer",
                    },
                }
            ],
        },
        "DefaultCacheBehavior": default_cache_behavior,
    }
    distribution = cf.create_distribution(DistributionConfig=config)["Distribution"]
    dist_id = distribution["Id"]
    cf.tag_resource(
        Resource=distribution["ARN"],
        Tags={"Items": [{"Key": "sim2real:managed", "Value": "true"}]},
    )
    ctx.on_cleanup(lambda: _delete_distribution(cf, dist_id))
    return dist_id


def _delete_distribution(cf, dist_id: str, timeout_s: float = 900.0, interval_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        resp = cf.get_distribution(Id=dist_id)
        if resp["Distribution"]["Status"] == "Deployed":
            cf.delete_distribution(Id=dist_id, IfMatch=resp["ETag"])
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"distribution {dist_id} never reached Deployed within {timeout_s}s")
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
