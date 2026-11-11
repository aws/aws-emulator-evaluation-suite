"""ipset-get-nonexistent-id-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ipset-get-nonexistent-id-rejected"
GROUP = 'ipset'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

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

def _delete_locked(w, name, scope, id_):
    """Refresh the LockToken then delete (WAFv2 delete_ip_set requires the current token)."""
    try:
        lt = w.get_ip_set(Name=name, Scope=scope, Id=id_)["LockToken"]
        w.delete_ip_set(Name=name, Scope=scope, Id=id_, LockToken=lt)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetIPSet returns a just-created IPSet's addresses by its Id, and fails with
    WAFNonexistentItemException and the exact not-found message for a well-formed unknown Id.
    """
    w = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-behav-waf-ips-")
    created = _retry_transient(
        lambda: w.create_ip_set(
            Name=name, Scope=SCOPE, IPAddressVersion="IPV4", Addresses=["10.0.0.0/8"]
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, name, SCOPE, created["Id"]))

    got = w.get_ip_set(Name=name, Scope=SCOPE, Id=created["Id"])
    assert got["IPSet"]["Addresses"] == ["10.0.0.0/8"], (
        f"positive control: expected the just-created IPSet's addresses, "
        f"got {got['IPSet'].get('Addresses')!r}"
    )

    code, message = _error_stable(
        lambda: w.get_ip_set(
            Name=ctx.unique_name("sim2real-behav-waf-ghost-"),
            Scope=SCOPE,
            Id="00000000-0000-0000-0000-000000000000",
        )
    )
    assert code == "WAFNonexistentItemException", (
        f"expected WAFNonexistentItemException for an unknown Id, got {code!r}"
    )
    assert message == "AWS WAF couldn’t perform the operation because your resource doesn’t exist.", message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
