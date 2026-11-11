"""put-metric-stream-concurrent-modification."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-metric-stream-concurrent-modification"
GROUP = 'concurrency'
SERVICES = ['cloudwatch']

_NON_CONCURRENT_ERROR_CODES = {
    # Any code OTHER than these on a racing writer is a genuine bug/regression,
    # not an expected contention outcome, and must fail the check.
    "ConcurrentModificationException",
    "ConflictException",
}


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
    """Concurrent PutMetricStream updates of one stream either succeed or fail with
    ConcurrentModificationException only, at least one wins, and the final IncludeFilters is exactly
    one successful writer's configuration, never a merged one."""
    cw = ctx.client("cloudwatch")
    account = ctx.client("sts").get_caller_identity()["Account"]
    stream_name = ctx.unique_name("sim2real-behav-cwprobe-mstream-cc-")
    # A fabricated Firehose/role is accepted -- CloudWatch does not eagerly
    # resolve them (see the metric-stream lifecycle check).
    firehose_arn = f"arn:aws:firehose:{ctx.region}:{account}:deliverystream/{stream_name}"
    role_arn = f"arn:aws:iam::{account}:role/{stream_name}"
    ctx.on_cleanup(lambda _n=stream_name: cw.delete_metric_stream(Name=_n))

    n = 10

    def put(i: int):
        return cw.put_metric_stream(
            Name=stream_name,
            FirehoseArn=firehose_arn,
            RoleArn=role_arn,
            OutputFormat="json",
            IncludeFilters=[{"Namespace": f"AWS/ConcurrencyProbe{i}"}],
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )

    results = _run_concurrent([lambda i=i: put(i) for i in range(n)], timeout_s=60)

    codes = _concurrent_error_codes(results)
    bad_codes = [c for c in codes if c not in _NON_CONCURRENT_ERROR_CODES]
    assert not bad_codes, f"unexpected error code(s) from concurrent PutMetricStream writers: {bad_codes}"

    successes = sum(1 for r in results if not isinstance(r, BaseException))
    assert successes >= 1, (
        f"at least one concurrent PutMetricStream writer must win; got 0 successes, codes={codes}"
    )
    winning_indices = {i for i, r in enumerate(results) if not isinstance(r, BaseException)}

    def get_stream():
        return cw.get_metric_stream(Name=stream_name)

    final = _poll_until(
        get_stream, lambda r: r.get("State") in ("running", "stopped"),
        timeout_s=30, interval_s=2, description="metric stream reaches a stable State",
    )
    final_namespaces = {f["Namespace"] for f in final.get("IncludeFilters", [])}
    assert len(final_namespaces) == 1, (
        f"final metric stream config must reflect exactly ONE writer's IncludeFilters, "
        f"not a corrupted/merged set, got {final_namespaces}"
    )
    winning_ns = next(iter(final_namespaces))
    winning_idx = int(winning_ns.replace("AWS/ConcurrencyProbe", ""))
    assert winning_idx in winning_indices, (
        f"final config (index {winning_idx}) must correspond to a writer that actually "
        f"reported success ({winning_indices}), got codes={codes}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
