"""concurrent-put-dashboard-optimistic-overwrite."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-dashboard-optimistic-overwrite"
GROUP = 'concurrency'
SERVICES = ['cloudwatch']

_NON_CONCURRENT_ERROR_CODES = {
    # Any code OTHER than these on a racing writer is a genuine bug/regression,
    # not an expected contention outcome, and must fail the check.
    "ConcurrentModificationException",
    "ConflictException",
}


def _dashboard_body(marker: str) -> str:
    return json.dumps(
        {
            "widgets": [
                {
                    "type": "text",
                    "x": 0,
                    "y": 0,
                    "width": 6,
                    "height": 3,
                    "properties": {"markdown": marker},
                }
            ]
        }
    )


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


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Ten concurrent PutDashboard calls on one name fail, if at all, only with a contention code,
    at least one succeeds, and GetDashboard returns exactly one writer's body, from a writer that
    reported success."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-cwprobe-dash-putcc-")
    ctx.on_cleanup(lambda _n=name: cw.delete_dashboards(DashboardNames=[_n]))
    n = 10

    def put(i: int):
        return cw.put_dashboard(DashboardName=name, DashboardBody=_dashboard_body(f"variant-{i}"))

    results = _run_concurrent([lambda i=i: put(i) for i in range(n)], timeout_s=60)

    codes = _concurrent_error_codes(results)
    bad_codes = [c for c in codes if c not in _NON_CONCURRENT_ERROR_CODES]
    assert not bad_codes, f"unexpected error code(s) from concurrent PutDashboard writers: {bad_codes}"

    successes = sum(1 for r in results if not isinstance(r, BaseException))
    assert successes >= 1, f"at least one concurrent PutDashboard writer must win; codes={codes}"
    winning_indices = {i for i, r in enumerate(results) if not isinstance(r, BaseException)}

    def get_body():
        try:
            return cw.get_dashboard(DashboardName=name)["DashboardBody"]
        except ClientError:
            return None

    final_body = _poll_until(
        get_body, lambda b: b is not None, timeout_s=30, interval_s=2,
        description="dashboard exists after the concurrent PutDashboard race",
    )

    matched = [i for i in range(n) if f"variant-{i}" in final_body]
    assert len(matched) == 1, (
        f"final dashboard body must reflect exactly ONE writer's content, not a merged/"
        f"corrupted body, got matches={matched} body={final_body!r}"
    )
    assert matched[0] in winning_indices, (
        f"final dashboard content (variant-{matched[0]}) must correspond to a writer that "
        f"actually reported success ({winning_indices}), got codes={codes}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
