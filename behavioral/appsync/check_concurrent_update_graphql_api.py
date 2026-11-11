"""concurrent-update-graphql-api."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-graphql-api"
GROUP = 'concurrency'
SERVICES = ['appsync']

def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results

def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))

def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Overlapping UpdateGraphqlApi calls on one API: at least one wins, every loser fails
    ConcurrentModificationException, and the API settles on exactly one attempted value."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY"
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    racers = 6

    def attempt(i):
        return svc.update_graphql_api(
            apiId=api_id, name=api["name"], authenticationType="API_KEY", queryDepthLimit=i + 1
        )

    results = _run_concurrent([lambda i=i: attempt(i) for i in range(racers)])
    successes = _concurrent_successes(results)
    codes = _concurrent_error_codes(results)
    assert successes >= 1, f"expected at least one UpdateGraphqlApi racer to win, got results={results!r}"
    assert successes + len(codes) == racers, (
        f"every UpdateGraphqlApi racer must resolve to either a success or an error, got {results!r}"
    )
    for code in codes:
        assert code == "ConcurrentModificationException", (
            f"expected every losing UpdateGraphqlApi racer to fail with ConcurrentModificationException, "
            f"got {code} (all codes: {codes!r})"
        )

    got = svc.get_graphql_api(apiId=api_id)["graphqlApi"]
    assert got["apiId"] == api_id, f"expected apiId {api_id!r} to be stable across the race, got {got.get('apiId')!r}"
    assert got.get("queryDepthLimit") in range(1, racers + 1), (
        f"expected the final queryDepthLimit to reflect one of the racing UpdateGraphqlApi calls, got {got!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
