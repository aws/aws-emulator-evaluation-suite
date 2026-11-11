"""list-ipsets-pagination-and-membership."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-ipsets-pagination-and-membership"
GROUP = 'listing'
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

def _list_all(list_fn, key, scope=SCOPE, limit=100):
    """Fully paginate one of the WAFv2 List* operations (marker-paginated).

    Detects a marker that fails to advance (repeats or loops) instead of spinning forever.
    """
    items = []
    seen_markers = set()
    marker = None
    while True:
        kwargs = {"Scope": scope, "Limit": limit}
        if marker:
            kwargs["NextMarker"] = marker
        resp = _retry_transient(lambda: list_fn(**kwargs))
        page = resp.get(key, [])
        items.extend(page)
        marker = resp.get("NextMarker")
        if not marker or not page:
            break
        assert marker not in seen_markers, f"ListIPSets NextMarker did not advance: {marker!r}"
        seen_markers.add(marker)
    return items

def _create_ipset(ctx, w, name=None, addresses=None, scope=SCOPE):
    """Create an IPSet (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-ips-")
    addresses = addresses if addresses is not None else ["10.0.0.0/8"]
    summary = _retry_transient(
        lambda: w.create_ip_set(
            Name=name, Scope=scope, IPAddressVersion="IPV4", Addresses=addresses,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "ip_set", name, scope, summary["Id"]))
    return summary

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListIPSets surfaces newly created sets and honours Limit/NextMarker paging."""
    w = ctx.client("wafv2")
    created = [_create_ipset(ctx, w)["Name"] for _ in range(3)]

    page = _retry_transient(lambda: w.list_ip_sets(Scope=SCOPE, Limit=1))
    assert len(page["IPSets"]) <= 1, page["IPSets"]
    assert page.get("NextMarker"), "Limit=1 with >1 IPSet must return a NextMarker"

    # Walk the whole listing one item per page, so NextMarker is actually exercised for
    # forward progress (not just checked for presence once) and duplicates would surface.
    all_names_list = [s["Name"] for s in _list_all(w.list_ip_sets, "IPSets", limit=1)]
    assert len(all_names_list) == len(set(all_names_list)), (
        f"ListIPSets pagination via NextMarker returned duplicates: {all_names_list}"
    )
    all_names = set(all_names_list)
    for name in created:
        assert name in all_names, f"{name} missing from ListIPSets"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
