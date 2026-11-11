"""concurrent-account-setting-writes."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "concurrent-account-setting-writes"
GROUP = 'overly-permissive'
SERVICES = ['ecs']


def _poll_until(fn, pred, *, timeout_s=60, interval_s=3, description=""):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fn()
        if pred(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"timed out waiting for {description!r} (last={last!r})")


def _error(fn):
    """Call fn(); return its botocore (code, message). An unexpected success raises:
    accepting a call that AWS refuses must not be reported as a mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:ecs-account-settings")
def run(ctx) -> None:
    """Racing PutAccountSettingDefault, then racing principal-scoped PutAccountSetting, each
    converge to exactly one of the two values; an invalid value and a re-delete of a removed
    override are rejected with InvalidParameterException."""
    ecs = ctx.client("ecs")
    setting_name = "containerInsights"

    code, message = _error(lambda: ecs.put_account_setting(name=setting_name, value="not-a-real-value"))
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "Invalid setting 'value'", f"unexpected message: {message!r}"

    # No principalArn: only the root user may name another principal, so writes target the
    # caller's own override. Both it and the account default are restored afterward.
    own_before = ecs.list_account_settings(name=setting_name, effectiveSettings=False)["settings"]
    ctx.on_cleanup(lambda: _restore_own_override(ecs, setting_name, own_before))
    if own_before:
        ecs.delete_account_setting(name=setting_name)
    snapshot = ecs.list_account_settings(name=setting_name, effectiveSettings=True)["settings"]
    assert len(snapshot) == 1, f"expected one effective setting to snapshot, got {snapshot}"
    original_default_value = snapshot[0]["value"]
    ctx.on_cleanup(
        lambda: ecs.put_account_setting_default(name=setting_name, value=original_default_value)
    )

    # --- Race 1: PutAccountSettingDefault with two different values ---------
    def _def_a():
        return ecs.put_account_setting_default(name=setting_name, value="enabled")

    def _def_b():
        return ecs.put_account_setting_default(name=setting_name, value="enhanced")

    results = _run_concurrent([_def_a, _def_b], timeout_s=30)
    successes = _concurrent_successes(results)
    assert successes == 2, (
        f"expected both concurrent PutAccountSettingDefault racers to succeed, got "
        f"{successes}/2 (codes: {_concurrent_error_codes(results)})"
    )

    final_default = _poll_until(
        lambda: ecs.list_account_settings(name=setting_name, effectiveSettings=True)["settings"],
        lambda s: len(s) == 1 and s[0]["value"] in ("enabled", "enhanced"),
        timeout_s=30,
        interval_s=2,
        description="the account default setting converges to one of the two racing values",
    )
    assert len(final_default) == 1 and final_default[0]["value"] in ("enabled", "enhanced"), (
        f"expected the settled account default to cleanly match ONE of ('enabled','enhanced'), "
        f"got {final_default}"
    )

    # --- Race 2: PutAccountSetting (principal-scoped) with two different values ---
    def _put_a():
        return ecs.put_account_setting(name=setting_name, value="enabled")

    def _put_b():
        return ecs.put_account_setting(name=setting_name, value="enhanced")

    results2 = _run_concurrent([_put_a, _put_b], timeout_s=30)
    successes2 = _concurrent_successes(results2)
    assert successes2 == 2, (
        f"expected both concurrent principal-scoped PutAccountSetting racers to succeed, got "
        f"{successes2}/2 (codes: {_concurrent_error_codes(results2)})"
    )

    final_principal = _poll_until(
        lambda: ecs.list_account_settings(name=setting_name, effectiveSettings=False)["settings"],
        lambda s: len(s) == 1 and s[0]["value"] in ("enabled", "enhanced"),
        timeout_s=30,
        interval_s=2,
        description="the principal-scoped account setting converges to one of the two racing values",
    )
    assert len(final_principal) == 1, (
        f"expected exactly ONE settled principal-scoped setting record, got {final_principal}"
    )
    assert final_principal[0]["value"] in ("enabled", "enhanced"), (
        f"expected the settled principal-scoped value to cleanly match ONE of the racing values, "
        f"got {final_principal[0]['value']}"
    )

    ecs.delete_account_setting(name=setting_name)

    after_delete = ecs.list_account_settings(name=setting_name, effectiveSettings=False)["settings"]
    assert not after_delete, (
        "expected no principal-scoped override for the caller after delete, "
        f"got {after_delete}"
    )
    redelete_code, redelete_message = _error(
        lambda: ecs.delete_account_setting(name=setting_name)
    )
    assert redelete_code == "InvalidParameterException", (
        f"expected re-delete of an already-deleted override to fail with "
        f"InvalidParameterException, got {redelete_code}"
    )
    assert redelete_message == "Referenced setting doesn't exist", f"unexpected message: {redelete_message!r}"


def _restore_own_override(ecs, setting_name, own_before):
    current = ecs.list_account_settings(name=setting_name, effectiveSettings=False)["settings"]
    if own_before:
        ecs.put_account_setting(name=setting_name, value=own_before[0]["value"])
    elif current:
        ecs.delete_account_setting(name=setting_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
