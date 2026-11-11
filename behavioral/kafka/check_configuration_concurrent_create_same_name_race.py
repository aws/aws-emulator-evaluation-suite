"""configuration-concurrent-create-same-name-race."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "configuration-concurrent-create-same-name-race"
GROUP = 'configuration'
SERVICES = ['kafka']

def _run_concurrent(fns, *, timeout_s=60):
    """Run callables in parallel; return results in submission order (a raised exception is
    captured as its slot's value rather than propagating)."""
    import concurrent.futures

    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:  # noqa: BLE001 — captured for the caller to assert on
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
    """Error codes for the _run_concurrent entries that raised (ClientError -> Error.Code,
    other exceptions -> class name); successes are skipped."""
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Four concurrent CreateConfiguration calls with the same Name: exactly one succeeds at revision 1,
    the other three fail with ConflictException "A resource with this name already exists.", and the
    configuration has only revision 1."""
    msk = ctx.client("kafka")
    name = ctx.unique_name("sim2real-behav-race-config-")
    props = b"num.partitions=1\n"

    def attempt():
        return msk.create_configuration(
            Name=name, KafkaVersions=["3.6.0"], ServerProperties=props
        )

    results = _run_concurrent([attempt for _ in range(4)])
    errors = _concurrent_error_codes(results)
    created = [r for r in results if isinstance(r, dict) and r.get("Arn")]

    for r in created:
        ctx.on_cleanup(lambda _a=r["Arn"]: msk.delete_configuration(Arn=_a))

    assert len(created) == 1, f"expected exactly 1 winner, got {len(created)}: {created}"
    assert len(errors) == 3, errors
    assert all(code == "ConflictException" for code in errors), errors
    messages = [r.response.get("Error", {}).get("Message") for r in results if isinstance(r, ClientError)]
    assert messages == ["A resource with this name already exists."] * 3, messages

    # The winner is a single configuration at revision 1 -- no duplicate writes.
    arn = created[0]["Arn"]
    assert created[0]["LatestRevision"]["Revision"] == 1, created[0]
    revisions = msk.list_configuration_revisions(Arn=arn)["Revisions"]
    assert [r["Revision"] for r in revisions] == [1], revisions

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
