"""health-check-concurrent-update-race."""

from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "health-check-concurrent-update-race"
GROUP = 'health-check'
SERVICES = ['route53']

_MANAGED_TAGS = [
    {"Key": "sim2real", "Value": CHECK},
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _caller_reference():
    return f"cr-{uuid.uuid4()}"


def _health_check_fqdn(ctx):
    """A name under the reserved .invalid TLD: it never resolves, so the health check probes no host."""
    return f"{ctx.unique_name('sim2real-behav-hc').lower()}.invalid"


def _create_health_check(ctx, r53, port=80):
    resp = r53.create_health_check(
        CallerReference=_caller_reference(),
        HealthCheckConfig={
            "FullyQualifiedDomainName": _health_check_fqdn(ctx),
            "Port": port,
            "Type": "HTTP",
            "ResourcePath": "/",
            "RequestInterval": 30,
            "FailureThreshold": 3,
        },
    )
    hc_id = resp["HealthCheck"]["Id"]
    ctx.on_cleanup(lambda i=hc_id: r53.delete_health_check(HealthCheckId=i))
    r53.change_tags_for_resource(
        ResourceType="healthcheck", ResourceId=hc_id, AddTags=_MANAGED_TAGS
    )
    return hc_id


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent UpdateHealthCheck calls with the same base version: exactly one wins, others get HealthCheckVersionMismatch."""
    r53 = ctx.client("route53")
    hc_id = _create_health_check(ctx, r53)
    v0 = r53.get_health_check(HealthCheckId=hc_id)["HealthCheck"]["HealthCheckVersion"]

    def attempt(path):
        return r53.update_health_check(HealthCheckId=hc_id, HealthCheckVersion=v0, ResourcePath=path)

    results = _run_concurrent([lambda p=f"/race-{i}": attempt(p) for i in range(5)])

    successes = _concurrent_successes(results)
    assert successes == 1, f"expected exactly one winner, got {successes}"

    errors = _concurrent_error_codes(results)
    assert len(errors) == 4, f"expected 4 losers, got {len(errors)}: {errors}"
    assert all(code == "HealthCheckVersionMismatch" for code in errors), errors
    expected = (
        f"Health check with id {hc_id} has version {v0 + 1}, but expected to have version {v0}. "
        "Could not proceed with update."
    )
    messages = [r.response["Error"].get("Message", "") for r in results if isinstance(r, ClientError)]
    assert messages == [expected] * 4, f"expected every loser's message to be {expected!r}, got {messages!r}"

    final = r53.get_health_check(HealthCheckId=hc_id)["HealthCheck"]
    assert final["HealthCheckVersion"] == v0 + 1, (
        f"version should advance by exactly 1 under contention, got {final['HealthCheckVersion']} from base {v0}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
