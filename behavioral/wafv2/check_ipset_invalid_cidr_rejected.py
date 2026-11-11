"""ipset-invalid-cidr-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ipset-invalid-cidr-rejected"
GROUP = 'overly-permissive'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

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
    """CreateIPSet rejects a non-CIDR address with WAFInvalidParameterException and the exact
    IP_ADDRESS message and stores no IPSet; the same request with a valid CIDR succeeds and round-trips.
    """
    w = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-behav-waf-ips-")
    code, message = _error_stable(
        lambda: w.create_ip_set(
            Name=name, Scope=SCOPE, IPAddressVersion="IPV4", Addresses=["not-an-ip-address/8"]
        )
    )
    assert code == "WAFInvalidParameterException", code
    assert message == "Error reason: The parameter contains formatting that is not valid., field: IP_ADDRESS, parameter: not-an-ip-address/8", message

    listed = _list_all(w.list_ip_sets, "IPSets")
    assert not any(s["Name"] == name for s in listed), listed

    created = w.create_ip_set(
        Name=name, Scope=SCOPE, IPAddressVersion="IPV4", Addresses=["192.0.2.0/24"],
        Tags=[{"Key": "Team", "Value": "sim2real"}],
    )["Summary"]
    ip_set_id = created["Id"]

    def _cleanup():
        current = w.get_ip_set(Name=name, Scope=SCOPE, Id=ip_set_id)
        w.delete_ip_set(
            Name=name, Scope=SCOPE, Id=ip_set_id, LockToken=current["LockToken"],
        )

    ctx.on_cleanup(_cleanup)
    got = w.get_ip_set(Name=name, Scope=SCOPE, Id=ip_set_id)["IPSet"]
    assert got["Addresses"] == ["192.0.2.0/24"], got["Addresses"]

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
