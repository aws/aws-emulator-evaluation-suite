"""cache-policy-invalid-ttl-order-rejected."""
from __future__ import annotations

import itertools

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ===== helpers =====
_COUNTER = itertools.count()


def _error(fn):
    """Run fn and return (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


# ===== end helpers =====

CHECK = "cache-policy-invalid-ttl-order-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']


def _cache_policy_config(name, *, min_ttl, default_ttl, max_ttl):
    return {
        "Comment": "sim2real ttl-order fidelity probe",
        "Name": name,
        "MinTTL": min_ttl,
        "DefaultTTL": default_ttl,
        "MaxTTL": max_ttl,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": True,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    }


def _custom_policy_names(cf):
    names = []
    marker = None
    while True:
        kwargs = {"Type": "custom", "MaxItems": "100"}
        if marker:
            kwargs["Marker"] = marker
        page = cf.list_cache_policies(**kwargs)["CachePolicyList"]
        for item in page.get("Items", []) or []:
            names.append(item["CachePolicy"]["CachePolicyConfig"]["Name"])
        marker = page.get("NextMarker")
        if not marker:
            return names


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCachePolicy refuses each violation of MinTTL <= DefaultTTL <= MaxTTL with InvalidArgument
    whose message states the TTL-order rule, so a generic or unrelated InvalidArgument fails.
    """
    cf = ctx.client("cloudfront")

    # The exact ordering rule real AWS quotes. Asserted on every leg because all three
    # violations share InvalidArgument, CloudFront's catch-all code.
    ttl_rule = (
        "MinTTL, MaxTTL and DefaultTTL should follow order MinTTL less than or equal to "
        "DefaultTTL less than or equal to MaxTTL"
    )

    legs = [
        # MaxTTL below MinTTL.
        ("MaxTTL(60) < MinTTL(3600)", "sim2real-behav-cp-badmax-", (3600, 86400, 60)),
        # DefaultTTL below MinTTL, with Min <= Max still holding.
        ("DefaultTTL(50) < MinTTL(100)", "sim2real-behav-cp-baddef-", (100, 50, 1000)),
        # DefaultTTL above MaxTTL, with Min <= Max still holding -- the leg an emulator
        # that only compares Min against Max lets through.
        ("DefaultTTL(5000) > MaxTTL(1000)", "sim2real-behav-cp-bigdef-", (100, 5000, 1000)),
    ]
    rejected_names = []
    for description, prefix, (min_ttl, default_ttl, max_ttl) in legs:
        name = ctx.unique_name(prefix)
        rejected_names.append(name)
        code, msg = _error(
            lambda n=name, a=min_ttl, b=default_ttl, c=max_ttl: cf.create_cache_policy(
                CachePolicyConfig=_cache_policy_config(
                    n, min_ttl=a, default_ttl=b, max_ttl=c
                )
            )
        )
        assert code == "InvalidArgument", (
            f"{description} must be refused with InvalidArgument -- NOT InvalidTTLOrder, "
            f"which CreateCachePolicy does not model at all (measured on real AWS); got "
            f"{code!r}: {msg!r}"
        )
        assert msg == ttl_rule, (
            f"{description}: the refusal must quote the ordering rule actually applied "
            f"({ttl_rule!r}) -- InvalidArgument is CloudFront's catch-all, so the message "
            f"is what attributes the refusal to the TTL chain; got {msg!r}"
        )

    # Effect absent: none of the rejected policies exists.
    existing = _custom_policy_names(cf)
    for name in rejected_names:
        assert name not in existing, f"{name} must not have been created"

    # 3. Control: the corrected ordering is accepted and the TTLs round-trip.
    good_name = ctx.unique_name("sim2real-behav-cp-ttlok-")
    created = cf.create_cache_policy(
        CachePolicyConfig=_cache_policy_config(
            good_name, min_ttl=100, default_ttl=500, max_ttl=1000
        )
    )
    policy_id = created["CachePolicy"]["Id"]

    def _cleanup():
        etag = cf.get_cache_policy(Id=policy_id)["ETag"]
        cf.delete_cache_policy(Id=policy_id, IfMatch=etag)

    ctx.on_cleanup(_cleanup)

    got = cf.get_cache_policy_config(Id=policy_id)["CachePolicyConfig"]
    assert (got["MinTTL"], got["DefaultTTL"], got["MaxTTL"]) == (100, 500, 1000), (
        f"TTLs must round-trip verbatim, got {(got['MinTTL'], got['DefaultTTL'], got['MaxTTL'])}"
    )
    assert good_name in _custom_policy_names(cf), (
        f"{good_name} must be listed under Type=custom after a successful create"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
