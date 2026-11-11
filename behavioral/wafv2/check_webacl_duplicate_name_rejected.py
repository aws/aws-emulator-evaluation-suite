"""webacl-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-duplicate-name-rejected"
GROUP = 'overly-permissive'
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
    """Return the ``Error`` (code and message) of the first NON-transient failure. Transient WAFv2
    codes are retried rather than reported, so an assertion about a semantic error is never polluted
    by throttling or propagation delay. An unexpected SUCCESS raises."""
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            error = {}
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                error = resp.get("Error", {})
            code = error.get("Code", "")
            if not code:
                raise
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                return error
            time.sleep(delay)
            continue
        raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")
    raise AssertionError("unreachable")

def _delete_locked(w, kind, name, scope, id_):
    """Refresh the LockToken then delete (WAFv2 delete_* require the current token); only an
    already-deleted resource (WAFNonexistentItemException) is tolerated."""
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    try:
        lt = getter(Name=name, Scope=scope, Id=id_)["LockToken"]
        deleter(Name=name, Scope=scope, Id=id_, LockToken=lt)
    except ClientError as err:
        if err.response["Error"]["Code"] != "WAFNonexistentItemException":
            raise

def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}

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

def _wait_absent(w, name, scope=SCOPE, attempts=10, delay=6.0):
    """Poll ListWebACLs until name drops out (delete propagation lag)."""
    listed = []
    for _attempt in range(attempts):
        listed = _list_all(w.list_web_acls, "WebACLs", scope)
        if not any(s["Name"] == name for s in listed):
            return
        time.sleep(delay)
    assert not any(s["Name"] == name for s in listed), (
        f"{name} still listed after delete propagation"
    )

def _retry_duplicate_lag(fn, attempts=10, delay=6.0):
    """Retry a recreate on WAFDuplicateItemException too: delete propagation
    can lag behind ListWebACLs, so the freed name may briefly still read as
    taken."""
    return _retry_transient(
        fn, attempts=attempts, delay=delay,
        codes=_TRANSIENT_CODES | {"WAFDuplicateItemException"},
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWebACL with a Name already used in the same Scope fails with WAFDuplicateItemException and the
    exact duplicate message, leaving one web ACL of that name; once it is deleted the same create
    succeeds.
    """
    w = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-behav-waf-acl-")
    live_id = []

    def _cleanup_live():
        if live_id:
            _delete_locked(w, "web_acl", name, SCOPE, live_id[-1])

    ctx.on_cleanup(_cleanup_live)

    tags_kw = {"Tags": [{"Key": "sim2real-check", "Value": CHECK}]}

    created = _retry_transient(
        lambda: w.create_web_acl(
            Name=name, Scope=SCOPE, DefaultAction={"Allow": {}}, Rules=[],
            VisibilityConfig=_visibility_config(name.replace("-", "")), **tags_kw,
        )
    )["Summary"]
    live_id.append(created["Id"])

    error = _error_stable(
        lambda: w.create_web_acl(
            Name=name, Scope=SCOPE, DefaultAction={"Block": {}}, Rules=[],
            VisibilityConfig=_visibility_config(name.replace("-", "") + "2"),
        )
    )
    assert error.get("Code") == "WAFDuplicateItemException", error
    assert error.get("Message") == (
        "AWS WAF couldn\u2019t perform the operation because some resource in your request "
        "is a duplicate of an existing one."
    ), error

    listed = _list_all(w.list_web_acls, "WebACLs")
    assert len([s for s in listed if s["Name"] == name]) == 1

    # Restore: free the name by deleting the original, then the identical
    # call must succeed.
    _delete_locked(w, "web_acl", name, SCOPE, created["Id"])
    live_id.clear()
    _wait_absent(w, name)

    recreated = _retry_duplicate_lag(
        lambda: w.create_web_acl(
            Name=name, Scope=SCOPE, DefaultAction={"Allow": {}}, Rules=[],
            VisibilityConfig=_visibility_config(name.replace("-", "") + "3"), **tags_kw,
        )
    )["Summary"]
    live_id.append(recreated["Id"])

    listed = _list_all(w.list_web_acls, "WebACLs")
    assert len([s for s in listed if s["Name"] == name]) == 1

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
