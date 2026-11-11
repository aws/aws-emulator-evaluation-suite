"""update-policy-engine-concurrent-edit-conflict."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-policy-engine-concurrent-edit-conflict"
GROUP = "concurrency"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdatePolicyEngine calls with different descriptions: each is applied or
    refused with ConflictException, and the engine settles on exactly one accepted call's
    description, never a refused call's or a merge."""
    bac = ctx.client("bedrock-agentcore-control")

    engine = bac.create_policy_engine(
        name=_alnum_name(ctx, "sim2realpe"),
        tags={"env": "sim2real-test", "purpose": "concurrent-edit-conflict"},
    )
    engine_id = engine["policyEngineId"]
    ctx.on_cleanup(lambda: bac.delete_policy_engine(policyEngineId=engine_id))
    _poll_until(
        lambda: bac.get_policy_engine(policyEngineId=engine_id),
        lambda r: r["status"] in ("ACTIVE", "CREATE_FAILED"),
        timeout_s=_wait_s(ctx, 60),
    )
    post_create = bac.get_policy_engine(policyEngineId=engine_id)
    assert post_create["status"] == "ACTIVE", f"expected ACTIVE, got {post_create['status']!r}"

    def _updater(desc):
        return lambda: bac.update_policy_engine(
            policyEngineId=engine_id, description={"optionalValue": desc}
        )

    results = _race([_updater("edit-a"), _updater("edit-b")])
    for ok, value in results:
        if not ok:
            code, message = value
            assert code == "ConflictException", f"undocumented UpdatePolicyEngine refusal: {code!r} ({message!r})"
            expected_message = (
                f"Concurrent modification on policy engine with ID {engine_id} detected, please try "
                "again once the policy engine status is ACTIVE"
            )
            assert message == expected_message, f"expected {expected_message!r}, got {message!r}"
    accepted = {d for (ok, _), d in zip(results, ("edit-a", "edit-b")) if ok}
    assert accepted, f"both UpdatePolicyEngine callers were refused: {results}"

    final = _poll_until(
        lambda: bac.get_policy_engine(policyEngineId=engine_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=_wait_s(ctx, 60),
    )
    assert final.get("description") in accepted, (
        f"description {final.get('description')!r} is not an accepted update {sorted(accepted)}: {final}"
    )


def _alnum_name(ctx, prefix):
    raw = ctx.unique_name(prefix + "-")
    return "".join(ch for ch in raw if ch.isalnum())


def _wait_s(ctx, cap_s):
    """cap_s, shortened so the wait ends before the runner's budget does."""
    left = ctx.time_left()
    if left is None:
        return cap_s
    return max(1.0, min(cap_s, left - 10.0))


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _race(fns, timeout_s=60.0):
    results: list = [None] * len(fns)
    barrier = threading.Barrier(len(fns))

    def _wrap(i, fn):
        barrier.wait()
        try:
            return i, True, fn()
        except ClientError as exc:
            return i, False, (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(_wrap, i, fn) for i, fn in enumerate(fns)]
        for fut in as_completed(futures, timeout=timeout_s):
            i, ok, value = fut.result()
            results[i] = (ok, value)
    return results


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
