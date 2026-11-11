"""concurrent-workgroup-create-duplicate-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-workgroup-create-duplicate-name"
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


def _concurrent_errors(results):
    errors = []
    for r in results:
        if isinstance(r, ClientError):
            errors.append((r.response.get('Error', {}).get('Code'), r.response.get('Error', {}).get('Message')))
        elif isinstance(r, BaseException):
            errors.append((type(r).__name__, str(r)))
    return errors


def _error(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateWorkGroup calls for one Name may all report success but leave exactly one
    workgroup of that name, and a later sequential create of it is rejected."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-wg-race-")
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True))
    n = 5

    def attempt():
        return athena.create_work_group(
            Name=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
        )

    results = _run_concurrent([attempt for _ in range(n)], timeout_s=90)
    successes = _concurrent_successes(results)
    errors = _concurrent_errors(results)
    # A loser racing the winner's in-flight create gets the generic conflict message; one that
    # arrives after the winner has committed gets the same refusal as a sequential duplicate.
    # Each is compared whole.
    race_conflict = ("InvalidRequestException", "The specified resource already exists.")
    duplicate = ("InvalidRequestException", "WorkGroup is already created")

    assert successes >= 1, f"at least one concurrent CreateWorkGroup must succeed, got {successes}"
    assert all(e == race_conflict or e == duplicate for e in errors), (
        f"concurrent losers may only fail with {race_conflict} or {duplicate}, got {errors}"
    )

    # The namespace must hold exactly one entry for the raced name.
    matching = [wg for wg in athena.list_work_groups()["WorkGroups"] if wg["Name"] == name]
    assert len(matching) == 1, f"expected exactly one workgroup named {name}, ListWorkGroups shows {len(matching)}"
    got_name = athena.get_work_group(WorkGroup=name)["WorkGroup"]["Name"]
    assert got_name == name, f"GetWorkGroup returned {got_name!r}, expected {name!r}"

    # Once settled, uniqueness IS enforced for a sequential duplicate.
    code, message = _error(lambda: athena.create_work_group(Name=name))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for a sequential duplicate after the race, got {code}"
    )
    assert message == "WorkGroup is already created", repr(message)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
