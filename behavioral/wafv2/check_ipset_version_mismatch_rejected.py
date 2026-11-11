"""ipset-version-mismatch-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "ipset-version-mismatch-rejected"
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
    """CreateIPSet rejects an IPv6 CIDR in an IPV4 set with WAFInvalidParameterException and the exact
    IP_ADDRESS message and stores no IPSet; the same name with an IPv4 CIDR succeeds and round-trips.
    """
    w = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-behav-waf-ips-")
    code, message = _error_stable(
        lambda: w.create_ip_set(
            Name=name, Scope=SCOPE, IPAddressVersion="IPV4", Addresses=["2001:db8::/32"]
        )
    )
    assert code == "WAFInvalidParameterException", code
    assert message == (
        "Error reason: The parameter contains formatting that is not valid., "
        "field: IP_ADDRESS, parameter: 2001:db8::/32"
    ), message

    listed = _list_all(w.list_ip_sets, "IPSets")
    assert not any(s["Name"] == name for s in listed), listed

    # Positive control: the same name, the same declared version, a
    # consistent IPv4 CIDR -- must succeed where the mismatched family was
    # refused, so the rejection above is shown to be about the mismatch and
    # not about this target refusing every CreateIPSet call.
    created = w.create_ip_set(
        Name=name, Scope=SCOPE, IPAddressVersion="IPV4", Addresses=["203.0.113.0/24"],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Summary"]
    ip_set_id = created["Id"]
    ctx.on_cleanup(lambda: w.delete_ip_set(
        Name=name, Scope=SCOPE, Id=ip_set_id,
        LockToken=w.get_ip_set(Name=name, Scope=SCOPE, Id=ip_set_id)["LockToken"],
    ))

    got = w.get_ip_set(Name=name, Scope=SCOPE, Id=ip_set_id)["IPSet"]
    assert got["Addresses"] == ["203.0.113.0/24"], got

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
