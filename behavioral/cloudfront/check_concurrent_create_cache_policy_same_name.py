"""concurrent-create-cache-policy-same-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _run_concurrent(fns, *, timeout_s=60):
    """Run callables in parallel; return results in submission order (exceptions captured, not raised)."""
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()
    def cap(fut, i):
        try:
            results[i] = fut.result()
        except Exception as e:  # noqa: BLE001 — captured for the caller to assert on
            results[i] = e
        resolved.add(i)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        f2i = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(f2i, timeout=timeout_s):
                cap(fut, f2i[fut])
        except concurrent.futures.TimeoutError as te:
            for fut, i in f2i.items():
                if i in resolved:
                    continue
                if fut.done():
                    cap(fut, i)
                else:
                    fut.cancel()
                    results[i] = te
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results

def _concurrent_successes(results):
    return sum(1 for r in results if not isinstance(r, BaseException))

def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes

def _minimal_cache_policy_config(name, **overrides):
    cfg = {
        "Comment": "behavioral test cache policy",
        "Name": name,
        "DefaultTTL": 86400,
        "MaxTTL": 31536000,
        "MinTTL": 1,
        "ParametersInCacheKeyAndForwardedToOrigin": {
            "EnableAcceptEncodingGzip": True,
            "EnableAcceptEncodingBrotli": False,
            "HeadersConfig": {"HeaderBehavior": "none"},
            "CookiesConfig": {"CookieBehavior": "none"},
            "QueryStringsConfig": {"QueryStringBehavior": "none"},
        },
    }
    cfg.update(overrides)
    return cfg

def _delete_cache_policy(cf, policy_id):
    etag = cf.get_cache_policy(Id=policy_id)["ETag"]
    cf.delete_cache_policy(Id=policy_id, IfMatch=etag)

CHECK = "concurrent-create-cache-policy-same-name"
GROUP = 'concurrency'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateCachePolicy calls with one Name: exactly one succeeds, every other fails
    with CachePolicyAlreadyExists and its exact message, and exactly one policy has that name."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-cp-race-")

    def make_cfg():
        return _minimal_cache_policy_config(name)

    n = 5
    results = _run_concurrent(
        [lambda: cf.create_cache_policy(CachePolicyConfig=make_cfg()) for _ in range(n)],
        timeout_s=60,
    )

    successes = _concurrent_successes(results)
    assert successes == 1, f"expected exactly 1 winner racing CreateCachePolicy({name}), got {successes}"

    error_codes = _concurrent_error_codes(results)
    assert len(error_codes) == n - 1, f"expected {n - 1} losers, got {len(error_codes)}"
    assert all(c == "CachePolicyAlreadyExists" for c in error_codes), (
        f"expected every loser to get CachePolicyAlreadyExists, got {error_codes}"
    )
    error_messages = {r.response.get("Error", {}).get("Message") for r in results if isinstance(r, ClientError)}
    assert error_messages == {"Another cache policy with the same name already exists within the aws account."}, (
        f"CachePolicyAlreadyExists messages of the losers: {error_messages}"
    )

    winner = next(r for r in results if not isinstance(r, BaseException))
    winner_id = winner["CachePolicy"]["Id"]
    ctx.on_cleanup(lambda: _delete_cache_policy(cf, winner_id))

    # Exactly one policy with this name must exist — not zero, not N.
    listed = cf.list_cache_policies(Type="custom")
    matches = [
        i
        for i in listed["CachePolicyList"]["Items"]
        if i.get("CachePolicy", {}).get("CachePolicyConfig", {}).get("Name") == name
    ]
    assert len(matches) == 1, f"expected exactly 1 CachePolicy named {name}, got {len(matches)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
