"""concurrent-prepared-statement-create-race."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-prepared-statement-create-race"
GROUP = 'concurrency'
SERVICES = ['athena']


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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent same-name CreatePreparedStatement calls: at least one succeeds, any loser fails
    InvalidRequestException, and GetPreparedStatement returns the statement with its query."""
    athena = ctx.client("athena")
    wg = ctx.unique_name("sim2real-behav-wg-psrace-")
    athena.create_work_group(Name=wg, Tags=[{"Key": "sim2real", "Value": "concurrent-prepared-statement-create-race"}])
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg, RecursiveDeleteOption=True))

    stmt_name = ctx.unique_name("sim2real-behav-stmt_race_").replace("-", "_")
    ctx.on_cleanup(lambda: athena.delete_prepared_statement(StatementName=stmt_name, WorkGroup=wg))

    def attempt():
        return athena.create_prepared_statement(StatementName=stmt_name, WorkGroup=wg, QueryStatement="SELECT 1")

    n = 5
    results = _run_concurrent([attempt for _ in range(n)], timeout_s=90)
    successes = _concurrent_successes(results)
    codes = _concurrent_error_codes(results)

    # Same-name creates may all succeed (last writer wins); any loser fails InvalidRequestException.
    assert successes >= 1, f"expected at least one CreatePreparedStatement to succeed, got {successes}"
    assert all(c == "InvalidRequestException" for c in codes), (
        f"expected any losing attempts to fail with InvalidRequestException, got {codes}"
    )

    # The name resolves to the statement with the query it was created with.
    got = athena.get_prepared_statement(StatementName=stmt_name, WorkGroup=wg)["PreparedStatement"]
    assert got["StatementName"] == stmt_name, got
    assert got["QueryStatement"] == "SELECT 1", got

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
