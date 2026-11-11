"""ipset-invalid-name-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ipset-invalid-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _error_stable(fn, attempts=10, delay=6.0):
    """Return (Code, Message) of the first NON-transient failure. Transient WAFv2 codes are
    retried rather than reported, so an assertion about a semantic error is never polluted by
    throttling or propagation delay. An unexpected SUCCESS raises, so an emulator accepting
    what AWS refuses never reads as a mere code mismatch."""
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            code, message = "", ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
                message = resp.get("Error", {}).get("Message", "")
            if code and code not in _TRANSIENT_CODES:
                return code, message
            if not code:
                raise
            if attempt == attempts - 1:
                return code, message
            time.sleep(delay)
            continue
        raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")
    raise AssertionError("unreachable")

def _list_all(list_fn, key, scope=SCOPE):
    """Fully paginate one of the WAFv2 List* operations (marker-paginated, 100/page)."""
    items = []
    marker = None
    while True:
        kwargs = {"Scope": scope, "Limit": 100}
        if marker:
            kwargs["NextMarker"] = marker
        resp = list_fn(**kwargs)
        page = resp.get(key, [])
        items.extend(page)
        marker = resp.get("NextMarker")
        if not marker or not page:
            break
    return items

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateIPSet rejects a Name with a character outside the allowed pattern with ValidationException
    and the exact pattern message and stores no IPSet; the same request with a valid Name succeeds and
    round-trips.
    """
    w = ctx.client("wafv2")
    bad_name = "sim2real behav bad name!"
    code, message = _error_stable(
        lambda: w.create_ip_set(
            Name=bad_name,
            Scope=SCOPE,
            IPAddressVersion="IPV4",
            Addresses=["10.0.0.0/8"],
        )
    )
    assert code == "ValidationException", code
    assert message == (
        f"1 validation error detected: Value '{bad_name}' at 'name' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: ^[\\w\\-]+$"
    ), message

    listed = _list_all(w.list_ip_sets, "IPSets")
    assert not any(s["Name"] == bad_name for s in listed), listed

    good_name = ctx.unique_name("sim2real-behav-waf-ips-")
    created = w.create_ip_set(
        Name=good_name, Scope=SCOPE, IPAddressVersion="IPV4", Addresses=["10.0.0.0/8"]
    )["Summary"]
    ip_set_id = created["Id"]

    def _cleanup():
        current = w.get_ip_set(Name=good_name, Scope=SCOPE, Id=ip_set_id)
        w.delete_ip_set(
            Name=good_name, Scope=SCOPE, Id=ip_set_id, LockToken=current["LockToken"]
        )

    ctx.on_cleanup(_cleanup)
    got = w.get_ip_set(Name=good_name, Scope=SCOPE, Id=ip_set_id)["IPSet"]
    assert got["Addresses"] == ["10.0.0.0/8"], got

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
