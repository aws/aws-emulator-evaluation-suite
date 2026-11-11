"""list-web-acls-membership."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-web-acls-membership"
GROUP = 'listing'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"
_NOT_FOUND = "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."

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

def _create_web_acl(ctx, w, name=None, rules=None, default_action=None, scope=SCOPE):
    """Create a WebACL (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-acl-")
    created = _retry_transient(
        lambda: w.create_web_acl(
            Name=name, Scope=scope,
            DefaultAction=default_action or {"Allow": {}},
            Rules=rules or [],
            VisibilityConfig=_visibility_config(name.replace("-", "")),
            Tags=[{"Key": "sim2real-check", "Value": "list-web-acls-membership"}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", name, scope, created["Id"]))
    return created

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListWebACLs reflects a created web ACL by name and ARN, and stops reflecting
    it once the ACL is deleted (delete_web_acl / get_web_acl both then refuse it)."""
    w = ctx.client("wafv2")
    summary = _create_web_acl(ctx, w)
    items = _list_all(w.list_web_acls, "WebACLs")
    match = [s for s in items if s["Name"] == summary["Name"]]
    assert len(match) == 1, f"expected 1 entry for {summary['Name']}, got {len(match)}"
    assert match[0]["ARN"] == summary["ARN"], (
        f"expected ARN {summary['ARN']!r}, got {match[0]['ARN']!r}"
    )

    lock_token = w.get_web_acl(Name=summary["Name"], Scope=SCOPE, Id=summary["Id"])["LockToken"]
    w.delete_web_acl(Name=summary["Name"], Scope=SCOPE, Id=summary["Id"], LockToken=lock_token)

    remaining = _list_all(w.list_web_acls, "WebACLs")
    assert not any(s["Name"] == summary["Name"] for s in remaining), (
        f"{summary['Name']} still listed by ListWebACLs after delete_web_acl"
    )
    try:
        w.get_web_acl(Name=summary["Name"], Scope=SCOPE, Id=summary["Id"])
    except Exception as exc:  # noqa: BLE001 - inspect error code
        resp = getattr(exc, "response", None)
        err = resp.get("Error", {}) if isinstance(resp, dict) else {}
        code = err.get("Code", "")
        assert code == "WAFNonexistentItemException", (
            f"expected WAFNonexistentItemException after delete, got {code!r} ({exc})"
        )
        assert err.get("Message") == _NOT_FOUND, err.get("Message")
    else:
        raise AssertionError("get_web_acl succeeded on a web ACL already deleted")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
