"""concurrent-configuration-set-create-exactly-one-wins."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-configuration-set-create-exactly-one-wins"
GROUP = 'configuration-set'
SERVICES = ['ses']

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
    """Concurrent CreateConfigurationSet on one name: exactly one wins, the rest lose (ConfigurationSetAlreadyExists or Throttling), and the set exists exactly once.

    A loser shed by SES's token bucket surfaces Throttling rather than reaching the
    ConfigurationSetAlreadyExists decision; both are legitimate loser outcomes.
    """
    ses = ctx.client("ses")
    name = ctx.unique_name("sim2real-behav-cfgset-race-")

    def create():
        return ses.create_configuration_set(ConfigurationSet={"Name": name})

    results = _run_concurrent([create for _ in range(8)], timeout_s=90)
    ctx.on_cleanup(lambda _n=name: ses.delete_configuration_set(ConfigurationSetName=_n))

    successes = _concurrent_successes(results)
    codes = _concurrent_error_codes(results)
    assert successes == 1, f"expected exactly 1 winner, got {successes} (codes={codes})"
    assert len(codes) == 7, f"expected 7 losers, got {codes}"
    assert all(
        c in ("ConfigurationSetAlreadyExists", "Throttling") for c in codes
    ), f"unexpected loser codes: {codes}"
    expected = f"Configuration set <{name}> already exists."
    for r in results:
        if isinstance(r, ClientError) and r.response.get("Error", {}).get("Code") == "ConfigurationSetAlreadyExists":
            message = r.response.get("Error", {}).get("Message")
            assert message == expected, f"expected {expected!r}, got {message!r}"

    # The configuration set really exists exactly once.
    names = [c["Name"] for c in ses.list_configuration_sets()["ConfigurationSets"]]
    assert names.count(name) == 1, f"expected exactly one configuration set named {name}, got {names.count(name)}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
