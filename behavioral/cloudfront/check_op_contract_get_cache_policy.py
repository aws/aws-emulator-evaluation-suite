"""op-contract-getCachePolicy."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-getCachePolicy"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]

# AWS managed cache policy (Managed-CachingOptimized) — always present, no
# provisioning required to exercise the success path.
_MANAGED_POLICY_ID = "658327ea-f89d-4fab-a63d-7e88639e58f6"


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCachePolicy returns the managed CachingOptimized policy (MinTTL 1) and a new custom policy with
    its Name, DefaultTTL and create ETag, refuses an unknown Id with NoSuchCachePolicy, and after the
    custom policy is deleted a read and a second delete return NoSuchCachePolicy."""
    cf = ctx.client("cloudfront")

    managed = cf.get_cache_policy(Id=_MANAGED_POLICY_ID)
    managed_cfg = managed["CachePolicy"]["CachePolicyConfig"]
    assert managed_cfg["Name"] == "Managed-CachingOptimized", (
        f"expected Managed-CachingOptimized, got {managed_cfg['Name']}"
    )
    # Fixed AWS-published constant for this managed policy id, not an
    # account-variable quota.
    assert managed_cfg["MinTTL"] == 1, f"expected MinTTL 1, got {managed_cfg['MinTTL']}"
    assert "ETag" in managed, f"expected ETag in response, got keys {list(managed)}"

    name = ctx.unique_name("sim2real-cp-")
    created = cf.create_cache_policy(
        CachePolicyConfig={
            "Name": name,
            "Comment": "sim2real behavioral check",
            "DefaultTTL": 60,
            "MaxTTL": 120,
            "MinTTL": 1,
            "ParametersInCacheKeyAndForwardedToOrigin": {
                "EnableAcceptEncodingGzip": False,
                "HeadersConfig": {"HeaderBehavior": "none"},
                "CookiesConfig": {"CookieBehavior": "none"},
                "QueryStringsConfig": {"QueryStringBehavior": "none"},
            },
        }
    )
    policy_id = created["CachePolicy"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete(cf, policy_id))

    fetched = cf.get_cache_policy(Id=policy_id)
    fetched_cfg = fetched["CachePolicy"]["CachePolicyConfig"]
    assert fetched_cfg["Name"] == name, f"expected name {name}, got {fetched_cfg['Name']}"
    assert fetched_cfg["DefaultTTL"] == 60, f"expected DefaultTTL 60, got {fetched_cfg['DefaultTTL']}"
    assert fetched["ETag"] == created["ETag"], (
        f"expected ETag {created['ETag']}, got {fetched['ETag']}"
    )

    # distinct error boundary: unknown Id
    code, msg = _error(lambda: cf.get_cache_policy(Id="00000000-0000-0000-0000-000000000000"))
    assert code == "NoSuchCachePolicy", f"expected NoSuchCachePolicy, got {code}"
    assert msg == "The specified cache policy does not exist.", f"unexpected NoSuchCachePolicy message: {msg!r}"

    # delete proves gone and unusable: an independent read 404s, and a
    # second delete on the same dead id gets the same specific error.
    cf.delete_cache_policy(Id=policy_id, IfMatch=fetched["ETag"])
    code, msg = _error(lambda: cf.get_cache_policy(Id=policy_id))
    assert code == "NoSuchCachePolicy", f"expected NoSuchCachePolicy after delete, got {code}"
    assert msg == "The specified cache policy does not exist.", f"unexpected NoSuchCachePolicy message after delete: {msg!r}"
    code, msg = _error(lambda: cf.delete_cache_policy(Id=policy_id, IfMatch=fetched["ETag"]))
    assert code == "NoSuchCachePolicy", f"expected NoSuchCachePolicy on double-delete, got {code}"
    assert msg == "The specified cache policy does not exist.", f"unexpected NoSuchCachePolicy message on double-delete: {msg!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe_delete(cf, policy_id: str) -> None:
    try:
        current = cf.get_cache_policy(Id=policy_id)
        cf.delete_cache_policy(Id=policy_id, IfMatch=current["ETag"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchCachePolicy":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
