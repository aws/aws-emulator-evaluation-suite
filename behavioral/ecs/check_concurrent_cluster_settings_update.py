"""concurrent-cluster-settings-update."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-cluster-settings-update"
GROUP = 'overly-permissive'
SERVICES = ['ecs']

# Retryable server-side conditions a racing UpdateClusterSettings can surface
# transiently (throttling under load, a not-yet-consistent just-created
# cluster, or the sibling racer's mutation still in flight). None is a real
# rejection of the request — the contract is that BOTH updates are ultimately
# accepted — so bounded-retry through them rather than counting them as failures.
_TRANSIENT_CODES = {
    "ThrottlingException",
    "Throttling",
    "TooManyRequestsException",
    "RequestLimitExceeded",
    "ServerException",
    "InternalServerError",
    "InternalFailure",
    "ServiceUnavailable",
    "ServiceUnavailableException",
    "UpdateInProgressException",
    "ConflictException",
    "ClusterNotFoundException",
}


def _retry_transient(fn, *, timeout_s=60, interval_s=2):
    """Call fn, retrying only on transient/throttle/contention ClientError codes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in _TRANSIENT_CODES or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    """UpdateClusterSettings with an unsupported containerInsights value is refused
    InvalidParameterException with the exact message; two concurrent updates with different
    values both succeed and DescribeClusters settles on one of them."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=[{"key": "sim2real", "value": "true"}])
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))

    def _settings():
        described = ecs.describe_clusters(clusters=[name], include=["SETTINGS"])["clusters"][0]
        return {s["name"]: s["value"] for s in described.get("settings", [])}

    # overly-permissive boundary: an invalid containerInsights value.
    code, message = _error(
        lambda: ecs.update_cluster_settings(
            cluster=name, settings=[{"name": "containerInsights", "value": "not-a-real-value"}]
        )
    )
    assert code == "InvalidParameterException", (
        f"expected InvalidParameterException for an unsupported settings value, got {code}"
    )
    assert message == "Invalid setting 'value'", f"unexpected message: {message!r}"
    rejected_settings = _settings()
    assert rejected_settings.get("containerInsights") != "not-a-real-value", (
        "the rejected containerInsights value must not appear on the cluster afterward, got "
        f"{rejected_settings!r}"
    )

    racing_values = ["enabled", "enhanced"]

    def _update(value):
        # The two updates race; ECS serializes cluster mutations, so a racer can
        # transiently see the sibling's mutation still in flight (or a throttle).
        # Bounded-retry through those transient conditions so BOTH updates are
        # ultimately accepted (the actual contract) — this does not relax the
        # settle/freeze invariants asserted below.
        return _retry_transient(
            lambda: ecs.update_cluster_settings(
                cluster=name, settings=[{"name": "containerInsights", "value": value}]
            ),
            timeout_s=60,
        )

    results = _run_concurrent([lambda v=v: _update(v) for v in racing_values], timeout_s=90)
    successes = _concurrent_successes(results)
    assert successes == len(racing_values), (
        f"expected every concurrent UpdateClusterSettings call to be individually accepted, got "
        f"{successes}/{len(racing_values)} successes (codes: {_concurrent_error_codes(results)})"
    )

    settled = _poll_until(
        _settings,
        lambda s: s.get("containerInsights") in racing_values,
        timeout_s=30,
        interval_s=2,
        description="the cluster's containerInsights setting converges to one of the racing values",
    )
    assert settled.get("containerInsights") in racing_values, (
        f"expected the settled containerInsights value to cleanly match ONE of {racing_values}, "
        f"got {settled.get('containerInsights')} (a value outside that set would indicate torn state)"
    )

    # Freeze check: repeated describes must all report the SAME settled value.
    observed = [_settings().get("containerInsights") for _ in range(3)]
    assert len(set(observed)) == 1, (
        f"expected repeated DescribeClusters calls to report a single stable value, got {observed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
