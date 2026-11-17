"""invalidation-cache-tag-paths-accepted-and-read-back."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalidation-cache-tag-paths-accepted-and-read-back"
GROUP = "invalidation"
SERVICES = ["cloudfront"]

#: The header CloudFront reads cache tags from, once CacheTagConfig names it. CloudFront echoes
#: a header name back lower-cased, so this is already lower-case to make the read-back exact.
_CACHE_TAG_HEADER = "x-sim2real-cache-tags"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """On a distribution with CacheTagConfig set, CreateInvalidation accepts a Paths item
    beginning with '#', alone and combined with an ordinary '/path' item, and GetInvalidation
    reports back the exact same paths rather than refusing the batch.
    """
    cf = ctx.client("cloudfront")
    did = _new_distribution(ctx)["Distribution"]["Id"]

    alone = ["#product:123"]
    inv_alone = _invalidate(cf, did, alone, ctx.unique_name("sim2real-inv-"))["Invalidation"]
    paths_alone = inv_alone["InvalidationBatch"]["Paths"]
    assert paths_alone["Quantity"] == 1 and paths_alone["Items"] == alone, (
        f"CreateInvalidation with a lone cache-tag path stored {paths_alone!r}, expected {alone!r}"
    )

    read_alone = cf.get_invalidation(DistributionId=did, Id=inv_alone["Id"])["Invalidation"]
    got_alone = read_alone["InvalidationBatch"]["Paths"]
    assert got_alone["Quantity"] == 1 and got_alone["Items"] == alone, (
        f"GetInvalidation reports {got_alone!r} for the lone cache-tag batch, expected {alone!r}"
    )

    mixed = ["#category:electronics", "/index.html"]
    inv_mixed = _invalidate(cf, did, mixed, ctx.unique_name("sim2real-inv-"))["Invalidation"]
    paths_mixed = inv_mixed["InvalidationBatch"]["Paths"]
    assert paths_mixed["Quantity"] == 2 and set(paths_mixed["Items"]) == set(mixed), (
        f"CreateInvalidation with a cache-tag path plus an ordinary path stored {paths_mixed!r}, "
        f"expected the set {sorted(mixed)!r}"
    )

    read_mixed = cf.get_invalidation(DistributionId=did, Id=inv_mixed["Id"])["Invalidation"]
    got_mixed = read_mixed["InvalidationBatch"]["Paths"]
    assert got_mixed["Quantity"] == 2 and set(got_mixed["Items"]) == set(mixed), (
        f"GetInvalidation reports {got_mixed!r} for the mixed batch, expected the set {sorted(mixed)!r}"
    )

    cfg = cf.get_distribution_config(Id=did)["DistributionConfig"]
    assert cfg["CacheTagConfig"] == {"HeaderName": _CACHE_TAG_HEADER}, (
        f"distribution's CacheTagConfig reads back as {cfg.get('CacheTagConfig')!r}, "
        f"expected HeaderName {_CACHE_TAG_HEADER!r}"
    )


#: AWS's managed "CachingOptimized" cache policy -- the id CDK's CachePolicy.CACHING_OPTIMIZED pins.
_CACHING_OPTIMIZED = "658327ea-f89d-4fab-a63d-7e88639e58f6"

#: A distribution can be deleted only once it is disabled and its last change has deployed,
#: which takes minutes; the teardown polls for that up to this deadline.
_DEPLOYED_DEADLINE_S = 900


def _new_distribution(ctx) -> dict:
    """Create a disabled distribution, with CacheTagConfig naming the tag header; register teardown.

    Disabled: an invalidation does not need the distribution to serve, and teardown skips disabling.
    """
    cf = ctx.client("cloudfront")
    ref = ctx.unique_name("sim2real-cf-")
    resp = cf.create_distribution(DistributionConfig=_distribution_config(ref))
    did = resp["Distribution"]["Id"]
    ctx.on_cleanup(lambda: _delete_distribution(ctx, did))
    return resp


def _distribution_config(ref: str) -> dict:
    return {
        "CallerReference": ref,
        "Comment": "sim2real cache-tag invalidation check",
        "Enabled": False,
        "DefaultRootObject": "index.html",
        "Origins": {"Quantity": 1, "Items": [{
            "Id": "site",
            "DomainName": "example.com",
            "CustomOriginConfig": {
                "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only",
            },
        }]},
        "DefaultCacheBehavior": {
            "TargetOriginId": "site",
            "ViewerProtocolPolicy": "redirect-to-https",
            "CachePolicyId": _CACHING_OPTIMIZED,
        },
        "CacheTagConfig": {"HeaderName": _CACHE_TAG_HEADER},
    }


def _delete_distribution(ctx, did: str) -> None:
    """Wait for the last change to deploy, delete. A failure raises."""
    cf = ctx.client("cloudfront")
    deadline = time.monotonic() + _DEPLOYED_DEADLINE_S
    while True:
        try:
            got = cf.get_distribution(Id=did)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "NoSuchDistribution":
                return
            raise
        dist = got["Distribution"]
        if dist["Status"] == "Deployed":
            cf.delete_distribution(Id=did, IfMatch=got["ETag"])
            return
        if time.monotonic() > deadline:
            raise AssertionError(
                f"cloudfront distribution {did} not deletable within "
                f"{_DEPLOYED_DEADLINE_S}s (status {dist['Status']!r})"
            )
        time.sleep(10)


def _invalidate(cf, did: str, paths: list[str], ref: str) -> dict:
    return cf.create_invalidation(DistributionId=did, InvalidationBatch={
        "Paths": {"Quantity": len(paths), "Items": paths},
        "CallerReference": ref,
    })


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
