"""concurrent-delete-security-group."""
from __future__ import annotations

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "concurrent-delete-security-group"
GROUP = 'concurrency'
SERVICES = ['rds']
ERR_DB_SECURITY_GROUP_NOT_FOUND = 'DBSecurityGroupNotFound'


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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent DeleteDBSecurityGroup calls on one group: exactly one succeeds, both other racers
    are rejected with DBSecurityGroupNotFound and its exact message, and a describe afterwards
    answers DBSecurityGroupNotFound with its own exact message."""
    rds = ctx.client('rds')
    name = ctx.unique_name('sim2real-behav-secg-')
    rds.create_db_security_group(
        DBSecurityGroupName=name,
        DBSecurityGroupDescription='behavioral check',
        Tags=[{'Key': 'sim2real', 'Value': 'true'}],
    )
    ctx.on_cleanup(lambda: _delete_unless_gone(rds, name))

    def delete_once():
        return rds.delete_db_security_group(DBSecurityGroupName=name)

    results = _run_concurrent([delete_once, delete_once, delete_once], timeout_s=60)
    successes = _concurrent_successes(results)
    assert successes == 1, f"expected exactly 1 winning delete, got {successes}: {results}"

    error_codes = _concurrent_error_codes(results)
    assert len(error_codes) == 2, f"expected 2 losers, got {len(error_codes)}"
    assert all(c == ERR_DB_SECURITY_GROUP_NOT_FOUND for c in error_codes), error_codes
    messages = [r.response["Error"].get("Message") for r in results if isinstance(r, ClientError)]
    assert messages == [f"DBSecurityGroup not found: {name}"] * 2, messages

    # Independent read at the destination: the group must actually be gone, not
    # merely reported gone by the racers' own delete responses.
    try:
        rds.describe_db_security_groups(DBSecurityGroupName=name)
        raise AssertionError("group still describable after the race resolved")
    except ClientError as exc:
        final_code = exc.response.get('Error', {}).get('Code')
        assert final_code == ERR_DB_SECURITY_GROUP_NOT_FOUND, (
            f"expected {ERR_DB_SECURITY_GROUP_NOT_FOUND} on independent read, got {final_code}"
        )
        final_message = exc.response.get('Error', {}).get('Message')
        assert final_message == f"DBSecurityGroup {name} not found.", final_message


def _delete_unless_gone(rds, name):
    """Delete the group; the race normally removed it already, so not-found is done."""
    try:
        rds.delete_db_security_group(DBSecurityGroupName=name)
    except ClientError as exc:
        if exc.response.get('Error', {}).get('Code') != ERR_DB_SECURITY_GROUP_NOT_FOUND:
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
