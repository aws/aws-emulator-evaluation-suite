"""regex-pattern-set-stale-locktoken-update-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "regex-pattern-set-stale-locktoken-update-rejected"
GROUP = 'regexpatternset'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

#: WAFOptimisticLockException's message for a write with a consumed LockToken.
LOCK_MESSAGE = (
    "AWS WAF couldn’t save your changes because someone changed the resource after you "
    "started to edit it. Reapply your changes."
)

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _retry_transient(fn, attempts=12, delay=6.0, codes=None):
    """Call fn, retrying WAFv2's transient control-plane errors (throttling /
    just-created-entity-not-yet-resolvable)."""
    retryable = codes or _TRANSIENT_CODES
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - inspect error code
            code = ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
            if code not in retryable:
                raise
            last_exc = exc
            if attempt == attempts - 1:
                break
            time.sleep(delay)
    raise last_exc

def _error_stable(fn, attempts=10, delay=6.0):
    """Return (code, message) of the first non-transient failure of fn; transient codes are
    retried. A call that succeeds raises AssertionError: the caller expects a refusal."""
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            resp = getattr(exc, "response", None)
            if not isinstance(resp, dict):
                raise
            err = resp.get("Error", {})
            code = err.get("Code", "")
            if not code:
                raise
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                return code, err.get("Message", "")
            time.sleep(delay)
            continue
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")
    raise AssertionError("unreachable: every attempt returns or raises")

_TEARDOWN_RETRY_CODES = (
    "WAFAssociatedItemException", "WAFOptimisticLockException", "WAFUnavailableEntityException"
)

def _delete_locked(w, kind, name, scope, id_):
    """Refresh the LockToken then delete (WAFv2 delete_* require the current token)."""
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    deadline = time.monotonic() + 25.0
    while True:
        try:
            lt = getter(Name=name, Scope=scope, Id=id_)["LockToken"]
            deleter(Name=name, Scope=scope, Id=id_, LockToken=lt)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "WAFNonexistentItemException":
                return
            # A reference or lock-token race still settling is retried; anything else raises.
            if code not in _TEARDOWN_RETRY_CODES or time.monotonic() >= deadline:
                raise
        time.sleep(2)

def _create_regex_pattern_set(ctx, w, name=None, patterns=None, scope=SCOPE):
    """Create a RegexPatternSet (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-rps-")
    regex_list = [{"RegexString": p} for p in (patterns or ["^foo.*"])]
    created = _retry_transient(
        lambda: w.create_regex_pattern_set(
            Name=name, Scope=scope, RegularExpressionList=regex_list,
            Tags=[{"Key": "sim2real:check", "Value": CHECK}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "regex_pattern_set", name, scope, created["Id"]))
    return created

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateRegexPatternSet with a consumed LockToken fails the optimistic lock and never lands,
    while an update with the current LockToken succeeds (positive control)."""
    w = ctx.client("wafv2")
    summary = _create_regex_pattern_set(ctx, w, patterns=["^/one"])
    name, set_id = summary["Name"], summary["Id"]
    stale_token = w.get_regex_pattern_set(Name=name, Scope=SCOPE, Id=set_id)["LockToken"]

    # Positive control: the legitimate first update moves the token forward, making
    # `stale_token` stale for any further call.
    first_update = _retry_transient(
        lambda: w.update_regex_pattern_set(
            Name=name, Scope=SCOPE, Id=set_id,
            RegularExpressionList=[{"RegexString": "^/two"}], LockToken=stale_token,
        )
    )
    current_token = first_update["NextLockToken"]

    # Break exactly one thing: reuse the now-stale `stale_token` for a second update.
    code, message = _error_stable(
        lambda: w.update_regex_pattern_set(
            Name=name, Scope=SCOPE, Id=set_id,
            RegularExpressionList=[{"RegexString": "^/three"}], LockToken=stale_token,
        )
    )
    assert code == "WAFOptimisticLockException", code
    assert message == LOCK_MESSAGE, message

    # Effect must be absent: the rejected ^/three write never landed.
    after_reject = w.get_regex_pattern_set(Name=name, Scope=SCOPE, Id=set_id)
    assert after_reject["RegexPatternSet"]["RegularExpressionList"] == [{"RegexString": "^/two"}], (
        f"stale-token update leaked through: {after_reject['RegexPatternSet']['RegularExpressionList']}"
    )
    assert after_reject["LockToken"] == current_token, (
        f"expected LockToken {current_token!r} unchanged by the rejected write, got {after_reject['LockToken']!r}"
    )

    # Restore: the same kind of update succeeds when it uses the current (non-stale)
    # LockToken -- the rejection above was about the token, not a blanket refusal.
    second_update = _retry_transient(
        lambda: w.update_regex_pattern_set(
            Name=name, Scope=SCOPE, Id=set_id,
            RegularExpressionList=[{"RegexString": "^/three"}], LockToken=current_token,
        )
    )
    assert second_update["NextLockToken"] != current_token, (
        f"expected the successful update to rotate the LockToken past {current_token!r}, "
        f"got the same token back"
    )
    after_success = w.get_regex_pattern_set(Name=name, Scope=SCOPE, Id=set_id)
    assert after_success["RegexPatternSet"]["RegularExpressionList"] == [{"RegexString": "^/three"}], (
        f"expected [^/three] after the fresh-token update, got {after_success['RegexPatternSet']['RegularExpressionList']}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
