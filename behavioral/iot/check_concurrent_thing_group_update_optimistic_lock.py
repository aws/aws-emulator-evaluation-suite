"""concurrent-thing-group-update-optimistic-lock."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-thing-group-update-optimistic-lock"
GROUP = 'concurrency'
SERVICES = ['iot']

def _delete_thing_group(iot, name):
    """Best-effort teardown: delete a thing group."""
    iot.delete_thing_group(thingGroupName=name)

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
    """N racers UpdateThingGroup with the SAME expectedVersion; exactly one wins the
    optimistic-lock race, the rest must get VersionConflictException."""
    iot = ctx.client("iot")
    group_name = ctx.unique_name("sim2real-behav-tg-race-")
    iot.create_thing_group(thingGroupName=group_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda _n=group_name: _delete_thing_group(iot, _n))

    initial_version = iot.describe_thing_group(thingGroupName=group_name)["version"]

    racers = 6
    descriptions = [f"racer-{i}" for i in range(racers)]
    calls = [
        (lambda d=d: iot.update_thing_group(
            thingGroupName=group_name,
            thingGroupProperties={"thingGroupDescription": d},
            expectedVersion=initial_version,
        ))
        for d in descriptions
    ]
    results = _run_concurrent(calls, timeout_s=90)

    successes = _concurrent_successes(results)
    error_codes = _concurrent_error_codes(results)

    assert successes == 1, f"expected exactly one winner of the optimistic-lock race, got {successes}"
    assert all(c == "VersionConflictException" for c in error_codes), (
        f"expected only VersionConflictException failures, got {error_codes}"
    )
    expected = f"The version for thing group {group_name} does not match the expected version."
    messages = [r.response.get("Error", {}).get("Message") for r in results if isinstance(r, ClientError)]
    assert all(message == expected for message in messages), (
        f"expected every loser's message {expected!r}, got {messages}"
    )

    final = iot.describe_thing_group(thingGroupName=group_name)
    final_version = final["version"]
    assert final_version == initial_version + 1, (
        f"exactly one successful update should advance the version by 1, got {final_version} from {initial_version}"
    )
    persisted = final["thingGroupProperties"]["thingGroupDescription"]
    assert persisted in descriptions, (
        f"persisted description {persisted!r} must be exactly one racer's write, not a torn "
        f"or merged value; candidates were {descriptions}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
