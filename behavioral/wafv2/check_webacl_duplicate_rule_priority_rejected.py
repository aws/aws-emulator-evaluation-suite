"""webacl-duplicate-rule-priority-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-duplicate-rule-priority-rejected"
GROUP = 'overly-permissive'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

def _retry_transient(fn, attempts=12, delay=6.0):
    """Call fn, retrying WAFv2's transient control-plane errors (throttling /
    just-created-entity-not-yet-resolvable)."""
    last_exc = None
    for attempt in range(attempts):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - inspect error code
            code = ""
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                code = resp.get("Error", {}).get("Code", "")
            if code not in _TRANSIENT_CODES:
                raise
            last_exc = exc
            if attempt == attempts - 1:
                break
            time.sleep(delay)
    raise last_exc

def _error_stable(fn, attempts=10, delay=6.0):
    """Return the ``Error`` (code and message) of the first NON-transient failure.
    Transient WAFv2 codes are retried rather than reported, so an assertion about a
    semantic error is never polluted by throttling or propagation delay. An unexpected
    SUCCESS raises, because a target ACCEPTING a call real AWS refuses must not be
    reported as a code mismatch."""
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
    """Refresh the LockToken then delete (WAFv2 delete_* require the current token). Already
    gone is clean; a reference still being released or a transient error is retried for 15 s."""
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    retryable = _TRANSIENT_CODES | {"WAFAssociatedItemException", "WAFOptimisticLockException"}
    deadline = time.monotonic() + 15.0
    while True:
        try:
            lt = getter(Name=name, Scope=scope, Id=id_)["LockToken"]
            deleter(Name=name, Scope=scope, Id=id_, LockToken=lt)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "WAFNonexistentItemException":
                return
            if code not in retryable or time.monotonic() >= deadline:
                raise
        time.sleep(2)

def _delete_by_name_if_exists(w, name, scope=SCOPE):
    """Cleanup for the negative path: if the rejected call created a WebACL anyway, find
    it by name (its Id is never returned) and delete it, so an over-permissive target never leaks."""
    for acl in _list_all(w.list_web_acls, "WebACLs", scope=scope):
        if acl["Name"] == name:
            _delete_locked(w, "web_acl", name, scope, acl["Id"])
            return

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

def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}

def _simple_rule(name, priority):
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {
            "ByteMatchStatement": {
                "SearchString": name.encode(),
                "FieldToMatch": {"UriPath": {}},
                "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                "PositionalConstraint": "CONTAINS",
            }
        },
        "Action": {"Count": {}},
        "VisibilityConfig": _visibility_config(name.replace("-", "")),
    }

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two rules sharing one Priority in a WebACL are rejected and leave no WebACL behind;
    the positive control with distinct priorities proves the rejection is due to the duplicate."""
    w = ctx.client("wafv2")
    name_ctrl = ctx.unique_name("sim2real-behav-waf-acl-ctrl-")
    name_dup = ctx.unique_name("sim2real-behav-waf-acl-dup-")

    # Positive control: the same call shape, distinct priorities.
    ctrl_rules = [_simple_rule("rule-a", 7), _simple_rule("rule-b", 8)]
    created = _retry_transient(
        lambda: w.create_web_acl(
            Name=name_ctrl, Scope=SCOPE, DefaultAction={"Allow": {}}, Rules=ctrl_rules,
            VisibilityConfig=_visibility_config(name_ctrl.replace("-", "")),
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", name_ctrl, SCOPE, created["Id"]))

    fetched = w.get_web_acl(Name=name_ctrl, Scope=SCOPE, Id=created["Id"])["WebACL"]
    assert sorted(r["Priority"] for r in fetched["Rules"]) == [7, 8], (
        f"the positive control did not persist priorities [7, 8]: {fetched['Rules']!r}"
    )

    # Negative: identical shape, duplicate priorities. Register cleanup by name before
    # the call, since an over-permissive target would create a WebACL whose Id we
    # never otherwise learn.
    ctx.on_cleanup(lambda: _delete_by_name_if_exists(w, name_dup))
    dup_rules = [_simple_rule("rule-a", 7), _simple_rule("rule-b", 7)]
    error = _error_stable(
        lambda: w.create_web_acl(
            Name=name_dup, Scope=SCOPE, DefaultAction={"Allow": {}}, Rules=dup_rules,
            VisibilityConfig=_visibility_config(name_dup.replace("-", "")),
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
    )
    assert error.get("Code") == "WAFInvalidParameterException", error
    assert error.get("Message") == (
        "Error reason: You have a duplicate priority. Priorities must be unique., "
        f"field: RULE, parameter: {dup_rules[1]['Priority']}"
    ), error

    # Effect-absent: the rejected create must not have produced a WebACL.
    listed = _list_all(w.list_web_acls, "WebACLs")
    assert not any(acl["Name"] == name_dup for acl in listed), (
        f"rejected CreateWebACL {name_dup!r} still appears in ListWebACLs"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
