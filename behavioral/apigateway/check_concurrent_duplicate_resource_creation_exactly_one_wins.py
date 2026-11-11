"""concurrent-duplicate-resource-creation-exactly-one-wins."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-duplicate-resource-creation-exactly-one-wins"
GROUP = 'concurrency'
SERVICES = ['apigateway']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateResource calls for one parent+pathPart leave exactly one durable resource.

    Reference: https://docs.aws.amazon.com/apigateway/latest/api/API_CreateResource.html"""
    ag = ctx.client("apigateway")
    api_id = _create_rest_api(ctx, ag)
    root_id = _root_resource_id(ag, api_id)

    def attempt():
        return ag.create_resource(restApiId=api_id, parentId=root_id, pathPart="racey")

    results = []
    raw_successes = 0
    # Bounded retry: if every racer got throttled (0 winners) the race never
    # actually happened, so re-run the burst rather than pass vacuously.
    for _ in range(3):
        results = _run_concurrent([attempt for _ in range(5)])
        raw_successes = _concurrent_successes(results)
        if raw_successes >= 1:
            break
        time.sleep(2)

    assert raw_successes >= 1, "expected at least one call to succeed, got none"

    error_codes = _concurrent_error_codes(results)
    # CreateResource is quota-limited to 5 req/s per account, so a racer may be throttled.
    allowed = {"ConflictException", "TooManyRequestsException"}
    assert set(error_codes) <= allowed, f"unexpected error codes: {error_codes}"

    # Under a tight race AWS can return 201 to more than one caller; all but one id then
    # 404 on GetResource, so durability is checked independently of the raw responses.
    winner_ids = [r["id"] for r in results if not isinstance(r, BaseException)]
    durable = _durable_resource_ids(ag, api_id, winner_ids)
    # Freeze detector: confirm the durable set is stable, not still converging --
    # a read taken too early after the burst could see a loser before it 404s.
    for _ in range(3):
        time.sleep(3)
        again = _durable_resource_ids(ag, api_id, winner_ids)
        if again == durable:
            break
        durable = again
    else:
        raise AssertionError(f"durable winner set did not settle across retries: {durable}")

    assert len(durable) == 1, (
        f"expected exactly one durable winner, got {len(durable)} of {len(winner_ids)} "
        f"raw successes {winner_ids}"
    )

    # Confirm the API's own listing agrees: exactly one "/racey" resource, and it is
    # the same id the independent per-resource read called durable.
    resources = ag.get_resources(restApiId=api_id)["items"]
    matching = [r for r in resources if r["path"] == "/racey"]
    assert len(matching) == 1, f"expected 1 '/racey' resource, found {len(matching)}"
    assert matching[0]["id"] == durable[0], (
        f"surviving resource {matching[0]['id']} does not match durable winner {durable[0]}"
    )


def _durable_resource_ids(ag, api_id, resource_ids):
    """The subset of `resource_ids` that an independent GetResource read still finds."""
    durable = []
    for rid in resource_ids:
        try:
            ag.get_resource(restApiId=api_id, resourceId=rid)
            durable.append(rid)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise
    return durable


# ===== helpers =====


def _delete_with_backoff(fn, *, deadline_s: float = 240.0) -> None:
    """Delete, retrying API Gateway's delete throttle (1 DeleteRestApi per 30 s per account) and
    in-flight conflicts every 2 s; an already-deleted resource is fine, any other error raises."""
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            retryable = ("TooManyRequestsException", "ConflictException", "LimitExceededException")
            if code not in retryable or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_rest_api(ctx, ag, name=None, **kwargs):
    """Create a REGIONAL REST API (registered for teardown) and return its id.

    REGIONAL is forced on purpose: the edge-optimized default is quota-limited to
    1 CreateRestApi every 30 seconds per account (vs 1 every 3 seconds regional).
    """
    name = name or ctx.unique_name("sim2real-behav-apigw-")
    kwargs.setdefault("endpointConfiguration", {"types": ["REGIONAL"]})
    kwargs.setdefault("tags", {"sim2real": CHECK})
    resp = ag.create_rest_api(name=name, **kwargs)
    api_id = resp["id"]
    ctx.on_cleanup(lambda: _delete_with_backoff(lambda: ag.delete_rest_api(restApiId=api_id)))
    return api_id


def _root_resource_id(ag, rest_api_id: str) -> str:
    """The id of the root ('/') resource of a REST API."""
    for item in ag.get_resources(restApiId=rest_api_id)["items"]:
        if item["path"] == "/":
            return item["id"]
    raise RuntimeError("root resource not found")


def _run_concurrent(fns, *, timeout_s=60):
    """Run callables in parallel; results in submission order (exceptions captured, not raised)."""
    import concurrent.futures

    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:  # noqa: BLE001 - captured for the caller to assert on
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


def _concurrent_successes(results) -> int:
    return sum(1 for r in results if not isinstance(r, BaseException))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
