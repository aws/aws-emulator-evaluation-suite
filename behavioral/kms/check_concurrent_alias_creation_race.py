"""concurrent-alias-creation-race."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-alias-creation-race"
GROUP = 'aliases'
SERVICES = ['kms']


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


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """When N racers concurrently try to bind the same new alias name to different keys, exactly one wins."""
    kms = ctx.client("kms")
    n = 5
    key_ids = []
    for i in range(n):
        kid = kms.create_key(
            Description=ctx.unique_name(f"kms-race-{i}-"),
            KeyUsage="ENCRYPT_DECRYPT",
            KeySpec="SYMMETRIC_DEFAULT",
            Tags=[{"TagKey": "sim2real", "TagValue": "kms-concurrent-alias-creation-race"}],
        )["KeyMetadata"]["KeyId"]
        ctx.on_cleanup(lambda _k=kid: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
        key_ids.append(kid)

    alias_name = f"alias/sim2real-behav-race-{uuid.uuid4().hex[:8]}"
    ctx.on_cleanup(lambda _a=alias_name: kms.delete_alias(AliasName=_a))

    fns = [
        (lambda _k=kid: kms.create_alias(AliasName=alias_name, TargetKeyId=_k))
        for kid in key_ids
    ]
    results = _run_concurrent(fns, timeout_s=90)

    successes = _concurrent_successes(results)
    codes = _concurrent_error_codes(results)
    assert successes == 1, f"expected exactly 1 winner, got {successes} (codes={codes})"
    assert codes.count("AlreadyExistsException") == n - 1, (
        f"expected {n - 1} AlreadyExistsException, got {codes}"
    )

    # the alias must end up pointing at exactly one of the racing keys
    winner = _poll_until(
        lambda: kms.describe_key(KeyId=alias_name)["KeyMetadata"]["KeyId"],
        lambda kid: kid in set(key_ids),
        timeout_s=30,
        interval_s=1.0,
        description="alias resolves to a racing key",
    )
    assert winner in set(key_ids), f"alias resolved to unexpected key {winner}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
