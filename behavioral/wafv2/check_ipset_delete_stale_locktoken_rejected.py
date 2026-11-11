"""ipset-delete-stale-locktoken-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ipset-delete-stale-locktoken-rejected"
GROUP = 'ipset'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

#: WAFNonexistentItemException's message for a deleted IP set.
NONEXISTENT_MESSAGE = "AWS WAF couldn’t perform the operation because your resource doesn’t exist."

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
    """Return (code, message) of the first NON-transient failure of fn.
    Transient WAFv2 codes are retried rather than reported, so an assertion about a
    semantic error is never polluted by throttling or propagation delay. A call that
    succeeds raises AssertionError: the caller expects a refusal."""
    for attempt in range(attempts):
        try:
            fn()
        except Exception as exc:  # noqa: BLE001
            resp = getattr(exc, "response", None)
            err = resp.get("Error", {}) if isinstance(resp, dict) else {}
            code = err.get("Code", "")
            if not code:
                raise
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                return code, err.get("Message", "")
            time.sleep(delay)
            continue
        raise AssertionError("expected the call to be refused, but it succeeded")
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

def _create_ipset(ctx, w, name=None, addresses=None, scope=SCOPE):
    """Create an IPSet (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-ips-")
    addresses = addresses if addresses is not None else ["10.0.0.0/8"]
    summary = _retry_transient(
        lambda: w.create_ip_set(
            Name=name, Scope=scope, IPAddressVersion="IPV4", Addresses=addresses,
            Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "ip_set", name, scope, summary["Id"]))
    return summary

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteIPSet with a LockToken already consumed by an update must fail the optimistic
    lock, the IPSet must survive that rejected delete, and deleting it with the CURRENT
    LockToken (the positive control) must succeed and be reflected as gone."""
    w = ctx.client("wafv2")
    ipset = _create_ipset(ctx, w)
    name, ipset_id = ipset["Name"], ipset["Id"]
    stale_token = w.get_ip_set(Name=name, Scope=SCOPE, Id=ipset_id)["LockToken"]

    updated = _retry_transient(
        lambda: w.update_ip_set(
            Name=name, Scope=SCOPE, Id=ipset_id,
            Addresses=["203.0.113.9/32"], LockToken=stale_token,
        )
    )
    current_token = updated["NextLockToken"]
    assert current_token != stale_token, "update did not advance the LockToken"

    code, message = _error_stable(
        lambda: w.delete_ip_set(
            Name=name, Scope=SCOPE, Id=ipset_id, LockToken=stale_token
        )
    )
    assert code == "WAFOptimisticLockException", code
    assert message == "AWS WAF couldn’t save your changes because someone changed the resource after you started to edit it. Reapply your changes.", message

    # Effect absent: the rejected delete must not have removed the IPSet.
    survived = w.get_ip_set(Name=name, Scope=SCOPE, Id=ipset_id)
    assert survived["IPSet"]["Id"] == ipset_id, "IPSet must survive a delete rejected for a stale LockToken"
    assert survived["LockToken"] == current_token, survived["LockToken"]

    # Positive control / restore: the identical delete call succeeds with the current token.
    _retry_transient(
        lambda: w.delete_ip_set(Name=name, Scope=SCOPE, Id=ipset_id, LockToken=current_token)
    )

    # The delete is proven: an independent read fails not-found.
    code_after, message_after = _error_stable(
        lambda: w.get_ip_set(Name=name, Scope=SCOPE, Id=ipset_id)
    )
    assert code_after == "WAFNonexistentItemException", code_after
    assert message_after == NONEXISTENT_MESSAGE, message_after

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
