"""apikey-lifecycle-create-list-delete."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "apikey-lifecycle-create-list-delete"
GROUP = 'apikey'
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAPIKey -> ListAPIKeys shows it -> DeleteAPIKey removes it from
    subsequent listings."""
    w = ctx.client("wafv2")
    resp = _retry_transient(
        lambda: w.create_api_key(Scope=SCOPE, TokenDomains=["example.com"])
    )
    api_key = resp["APIKey"]
    ctx.on_cleanup(lambda: w.delete_api_key(Scope=SCOPE, APIKey=api_key))

    listed = _list_all(w.list_api_keys, "APIKeySummaries")
    keys = [s["APIKey"] for s in listed]
    assert api_key in keys, f"expected created key {api_key!r} in ListAPIKeys, got {keys!r}"

    _retry_transient(lambda: w.delete_api_key(Scope=SCOPE, APIKey=api_key))

    listed2 = _list_all(w.list_api_keys, "APIKeySummaries")
    keys2 = [s["APIKey"] for s in listed2]
    assert api_key not in keys2, (
        f"expected deleted key {api_key!r} absent from ListAPIKeys, still present in {keys2!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
