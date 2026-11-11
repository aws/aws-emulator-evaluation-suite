"""concurrent-update-data-source."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _delete_if_present(fn):
    """Teardown for a resource the check's own delete race may already have removed."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

CHECK = "concurrent-update-data-source"
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

_DS_LOCKED = "Data source locked due to concurrent update, please retry"
_DELETE_LOCKED = "DataSource locked due to concurrent update, please retry"
_SCHEMA_BUSY = "Schema is currently being altered, please wait until that is complete."

def _error_pairs(results):
    """(code, message) of every racer that failed, in submission order."""
    pairs = []
    for r in results:
        if isinstance(r, ClientError):
            err = r.response.get("Error", {})
            pairs.append((err.get("Code"), err.get("Message")))
        elif isinstance(r, BaseException):
            pairs.append((type(r).__name__, str(r)))
    return pairs

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
    """Concurrent UpdateDataSource losers get ConcurrentModificationException; a concurrent delete race
    has exactly one winner, the rest NotFound/ConcurrentModification, then GetDataSource 404s."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    ds_name = ctx.unique_name("sim2real_behav_ds_").replace("-", "_")
    svc.create_data_source(apiId=api_id, name=ds_name, type="NONE")
    ctx.on_cleanup(lambda: _delete_if_present(lambda: svc.delete_data_source(apiId=api_id, name=ds_name)))
    racers = 5

    def update_attempt(i):
        return svc.update_data_source(
            apiId=api_id, name=ds_name, type="NONE", description=f"sim2real-behav-desc-{i}"
        )

    results = _run_concurrent([lambda i=i: update_attempt(i) for i in range(racers)])
    successes = _concurrent_successes(results)
    codes = _concurrent_error_codes(results)
    assert successes >= 1, f"expected at least one UpdateDataSource racer to win, got results={results!r}"
    assert successes + len(codes) == racers, (
        f"every UpdateDataSource racer must resolve to either a success or an error, got {results!r}"
    )
    for code, message in _error_pairs(results):
        assert (code, message) == ("ConcurrentModificationException", _DS_LOCKED), (
            f"expected every losing UpdateDataSource racer to fail with ConcurrentModificationException "
            f"{_DS_LOCKED!r}, got {code} {message!r} (all codes: {codes!r})"
        )

    got = svc.get_data_source(apiId=api_id, name=ds_name)["dataSource"]
    assert got["description"].startswith("sim2real-behav-desc-"), (
        f"expected the winning UpdateDataSource to persist, got {got!r}"
    )

    del_results = _run_concurrent(
        [lambda: svc.delete_data_source(apiId=api_id, name=ds_name) for _ in range(3)]
    )
    del_successes = _concurrent_successes(del_results)
    assert del_successes == 1, (
        f"expected exactly 1 DeleteDataSource racer to win, got {del_successes} (results={del_results!r})"
    )
    for code, message in _error_pairs(del_results):
        # A loser overlaps the winner's schema change or its data-source lock, or arrives after
        # the delete finished; each is graded on its own exact message.
        if code == "ConcurrentModificationException" and message == _SCHEMA_BUSY:
            pass
        elif code == "ConcurrentModificationException":
            assert message == _DELETE_LOCKED, f"DeleteDataSource loser: {code} {message!r}"
        else:
            assert (code, message) == ("NotFoundException", f"Data source {ds_name} not found"), (
                f"expected a losing DeleteDataSource racer to fail with ConcurrentModificationException "
                f"or NotFoundException, got {code} {message!r}"
            )

    code_after, message_after = _error(lambda: svc.get_data_source(apiId=api_id, name=ds_name))
    assert code_after == "NotFoundException", (
        f"expected NotFoundException from GetDataSource after the delete race settled, got {code_after}"
    )
    assert message_after == f"Data source {ds_name} not found", (
        f"expected the exact NotFound message from GetDataSource, got {message_after!r}"
    )

    code_update_after, message_update_after = _error(
        lambda: svc.update_data_source(apiId=api_id, name=ds_name, type="NONE", description="post-delete")
    )
    assert code_update_after == "NotFoundException", (
        f"expected UpdateDataSource on the deleted data source to fail with NotFoundException, "
        f"got {code_update_after}"
    )
    assert message_update_after == f"Data source {ds_name} not found", (
        f"expected the exact NotFound message from UpdateDataSource, got {message_update_after!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
