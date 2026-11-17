"""cache-policy-negative-min-ttl-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cache-policy-negative-min-ttl-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]

#: CreateCachePolicy's exact refusal for a MinTTL outside its allowed range.
_NEGATIVE_MIN_TTL = ("InvalidArgument", "The parameter MinTTL is not within allowed range.")


def expect_error(fn, code, message) -> None:
    """Assert fn raises a ClientError with exactly (code, message); raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        assert err["Code"] == code, f"expected {code!r}, got {err['Code']!r}: {err.get('Message')!r}"
        assert err.get("Message") == message, (
            f"expected message {message!r}, got {err.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_with_etag(get_fn, delete_fn, resource_id) -> None:
    delete_fn(Id=resource_id, IfMatch=get_fn(Id=resource_id)["ETag"])


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


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


def _policy_config(name, *, min_ttl, default_ttl, max_ttl):
    return {
        "Name": name,
        "Comment": "sim2real MinTTL range probe",
        "MinTTL": min_ttl,
        "DefaultTTL": default_ttl,
        "MaxTTL": max_ttl,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": False,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCachePolicy refuses a negative MinTTL with InvalidArgument and its exact message,
    and creates no policy; a MinTTL of 0 on an otherwise identical config is accepted.
    """
    cf = ctx.client("cloudfront")

    bad_name = ctx.unique_name("sim2real-behav-cfminttl-bad-")
    expect_error(
        lambda: cf.create_cache_policy(
            CachePolicyConfig=_policy_config(bad_name, min_ttl=-1, default_ttl=0, max_ttl=3600)
        ),
        *_NEGATIVE_MIN_TTL,
    )

    existing = _custom_policy_names(cf)
    assert bad_name not in existing, f"{bad_name} must not have been created"

    # Positive control: the identical config with MinTTL=0 is accepted and round-trips.
    good_name = ctx.unique_name("sim2real-behav-cfminttl-ok-")
    created = cf.create_cache_policy(
        CachePolicyConfig=_policy_config(good_name, min_ttl=0, default_ttl=0, max_ttl=3600)
    )
    policy_id = created["CachePolicy"]["Id"]
    ctx.on_cleanup(_teardown(
        lambda: _delete_with_etag(cf.get_cache_policy, cf.delete_cache_policy, policy_id),
        "NoSuchCachePolicy"))

    got = cf.get_cache_policy_config(Id=policy_id)["CachePolicyConfig"]
    assert got["MinTTL"] == 0, f"MinTTL must round-trip as 0, got {got['MinTTL']!r}"
    assert good_name in _custom_policy_names(cf), (
        f"{good_name} must be listed under Type=custom after a successful create"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
