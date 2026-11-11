"""concurrent-delete-parameter-group."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "concurrent-delete-parameter-group"
GROUP = 'concurrency'
SERVICES = ['rds']

ERR_DB_PARAMETER_GROUP_NOT_FOUND = "DBParameterGroupNotFound"
# A racing delete may catch the group mid-removal (the winner's delete is still
# in flight) and be refused with InvalidDBParameterGroupState instead of
# DBParameterGroupNotFound; both are legitimate "you did not win the race"
# rejections rather than a spurious success.
ERR_DB_PARAMETER_GROUP_INVALID_STATE = "InvalidDBParameterGroupState"
_LOSER_ERROR_CODES = frozenset({
    ERR_DB_PARAMETER_GROUP_NOT_FOUND,
    ERR_DB_PARAMETER_GROUP_INVALID_STATE,
})


def _default_param_family(ctx, engine: str) -> str:
    """DBParameterGroupFamily of the current default engine version for
    *engine* (e.g. "mysql"). Derived dynamically so the family never drifts as
    AWS rotates the default away."""
    rds = ctx.client("rds")
    resp = rds.describe_db_engine_versions(Engine=engine, DefaultOnly=True)
    versions = resp.get("DBEngineVersions", [])
    if not versions:
        versions = rds.describe_db_engine_versions(Engine=engine).get("DBEngineVersions", [])
    return versions[0]["DBParameterGroupFamily"]


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


def _delete_unless_gone(delete, gone_code):
    """Teardown delete; an already-deleted resource answers ``gone_code`` (documented not-found)."""
    try:
        delete()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent DeleteDBParameterGroup calls on one unattached group: exactly one succeeds, every
    other is rejected with DBParameterGroupNotFound or InvalidDBParameterGroupState, and a separate
    DescribeDBParameterGroups confirms the group is gone."""
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-pg-race-")
    rds.create_db_parameter_group(
        DBParameterGroupName=name,
        DBParameterGroupFamily=_default_param_family(ctx, "mysql"),
        Description="behavioral check",
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_unless_gone(
        lambda: rds.delete_db_parameter_group(DBParameterGroupName=name), "DBParameterGroupNotFound"))

    def delete_once():
        return rds.delete_db_parameter_group(DBParameterGroupName=name)

    n = 3
    results = _run_concurrent([delete_once for _ in range(n)], timeout_s=60)
    successes = _concurrent_successes(results)
    assert successes == 1, f"expected exactly 1 winning delete, got {successes}: {results}"

    error_codes = _concurrent_error_codes(results)
    assert len(error_codes) == n - 1, f"expected {n - 1} losers, got {len(error_codes)}"
    assert all(c in _LOSER_ERROR_CODES for c in error_codes), error_codes

    # Independent terminal read at the destination, through a different operation than the
    # one that raced (Describe, not Delete): the winner's delete must actually be visible.
    try:
        rds.describe_db_parameter_groups(DBParameterGroupName=name)
    except ClientError as exc:
        final_code = exc.response.get("Error", {}).get("Code")
        assert final_code == ERR_DB_PARAMETER_GROUP_NOT_FOUND, final_code
        final_message = exc.response.get("Error", {}).get("Message")
        assert final_message == f"DBParameterGroup not found: {name}", final_message
    else:
        raise AssertionError(
            f"expected {name} to be gone after the winning delete, but "
            "describe_db_parameter_groups still found it"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
