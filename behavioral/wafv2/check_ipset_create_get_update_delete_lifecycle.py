"""ipset-create-get-update-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ipset-create-get-update-delete-lifecycle"
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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """IPSet: create -> Get returns LockToken -> Update with token changes
    Addresses and rotates the token -> Delete with the new token succeeds."""
    w = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-behav-waf-ips-")
    created = _retry_transient(
        lambda: w.create_ip_set(
            Name=name, Scope=SCOPE, IPAddressVersion="IPV4", Addresses=["10.0.0.0/8"],
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "ip_set", name, SCOPE, created["Id"]))

    got = w.get_ip_set(Name=name, Scope=SCOPE, Id=created["Id"])
    assert got["IPSet"]["Addresses"] == ["10.0.0.0/8"], got["IPSet"]["Addresses"]
    lock_token = got["LockToken"]
    assert lock_token, got

    updated = _retry_transient(
        lambda: w.update_ip_set(
            Name=name, Scope=SCOPE, Id=created["Id"],
            Addresses=["10.0.0.0/8", "192.168.1.0/24"], LockToken=lock_token,
        )
    )
    next_token = updated["NextLockToken"]
    assert next_token != lock_token, "LockToken must rotate on every mutation"

    got2 = w.get_ip_set(Name=name, Scope=SCOPE, Id=created["Id"])
    assert sorted(got2["IPSet"]["Addresses"]) == sorted(["10.0.0.0/8", "192.168.1.0/24"]), (
        got2["IPSet"]["Addresses"]
    )
    assert got2["LockToken"] == next_token, (got2["LockToken"], next_token)

    _retry_transient(
        lambda: w.delete_ip_set(
            Name=name, Scope=SCOPE, Id=created["Id"], LockToken=got2["LockToken"]
        )
    )

    code, message = _error_stable(
        lambda: w.get_ip_set(Name=name, Scope=SCOPE, Id=created["Id"])
    )
    assert code == "WAFNonexistentItemException", code
    assert message == NONEXISTENT_MESSAGE, message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
