"""ipset-update-stale-locktoken-rejected."""
from __future__ import annotations

import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ipset-update-stale-locktoken-rejected"
GROUP = 'ipset'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"
_STALE_LOCK = (
    "AWS WAF couldn\u2019t save your changes because someone changed the resource after you "
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

def _error(fn):
    """Call fn(); return the botocore Error (Code, Message). An unexpected SUCCESS raises, so
    an emulator accepting what AWS refuses never reads as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

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
            Name=name, Scope=scope, IPAddressVersion="IPV4", Addresses=addresses
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "ip_set", name, scope, summary["Id"]))
    return summary


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateIPSet with a LockToken from before a concurrent update must fail
    with WAFOptimisticLockException, not silently overwrite."""
    w = ctx.client("wafv2")
    summary = _create_ipset(ctx, w, addresses=["10.0.0.0/8"])
    got = w.get_ip_set(Name=summary["Name"], Scope=SCOPE, Id=summary["Id"])
    stale_token = got["LockToken"]

    _retry_transient(
        lambda: w.update_ip_set(
            Name=summary["Name"], Scope=SCOPE, Id=summary["Id"],
            Addresses=["10.0.0.0/8", "172.16.0.0/12"], LockToken=stale_token,
        )
    )

    code, message = _error(
        lambda: w.update_ip_set(
            Name=summary["Name"], Scope=SCOPE, Id=summary["Id"],
            Addresses=["10.0.0.0/8", "203.0.113.0/24"], LockToken=stale_token,
        )
    )
    assert code == "WAFOptimisticLockException", (
        f"expected WAFOptimisticLockException for a reused stale LockToken, got {code!r}"
    )
    assert message == _STALE_LOCK, message

    after_reject = w.get_ip_set(Name=summary["Name"], Scope=SCOPE, Id=summary["Id"])
    assert sorted(after_reject["IPSet"]["Addresses"]) == sorted(["10.0.0.0/8", "172.16.0.0/12"]), (
        f"the rejected stale-token update must not have changed the addresses: "
        f"{after_reject['IPSet']['Addresses']!r}"
    )
    current_token = after_reject["LockToken"]
    assert current_token != stale_token, "the current LockToken must differ from the stale one"

    # Positive control after the rejection: the same kind of update, using the CURRENT
    # LockToken, still succeeds -- proving the refusal was specific to the stale token and
    # did not wedge the resource.
    _retry_transient(
        lambda: w.update_ip_set(
            Name=summary["Name"], Scope=SCOPE, Id=summary["Id"],
            Addresses=["10.0.0.0/8", "203.0.113.0/24"], LockToken=current_token,
        )
    )
    final = w.get_ip_set(Name=summary["Name"], Scope=SCOPE, Id=summary["Id"])
    assert sorted(final["IPSet"]["Addresses"]) == sorted(["10.0.0.0/8", "203.0.113.0/24"]), (
        f"the update with the current LockToken did not take effect: "
        f"{final['IPSet']['Addresses']!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
