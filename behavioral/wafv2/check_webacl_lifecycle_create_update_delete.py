"""webacl-lifecycle-create-update-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-lifecycle-create-update-delete"
GROUP = 'webacl'
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
    """Return the ``Error`` (code, message and ``HTTPStatusCode``) of the first NON-transient
    failure. Transient WAFv2 codes are retried rather than reported, so an assertion about a
    semantic error is never polluted by throttling or propagation delay. An unexpected SUCCESS
    raises."""
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            error = {}
            resp = getattr(exc, "response", None)
            if isinstance(resp, dict):
                error = dict(resp.get("Error", {}))
                error["HTTPStatusCode"] = resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
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
    """Refresh the LockToken then delete (WAFv2 delete_* require the current token). Tolerates
    only WAFNonexistentItemException (the body already deleted it)."""
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    try:
        lt = getter(Name=name, Scope=scope, Id=id_)["LockToken"]
        deleter(Name=name, Scope=scope, Id=id_, LockToken=lt)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "WAFNonexistentItemException":
            raise

def _list_web_acl_ids(w, scope):
    """Every WebACL id in *scope*, following NextMarker."""
    ids, kwargs = set(), {"Scope": scope, "Limit": 100}
    while True:
        page = w.list_web_acls(**kwargs)
        ids.update(acl["Id"] for acl in page["WebACLs"])
        marker = page.get("NextMarker")
        if not marker or not page["WebACLs"]:
            return ids
        kwargs["NextMarker"] = marker

def _assert_nonexistent(error, what, expected_message):
    """WAFNonexistentItemException + an HTTP 4xx + the exact message (AWS's wording does not name the id)."""
    assert error.get("Code") == "WAFNonexistentItemException", f"{what}: expected WAFNonexistentItemException, got {error!r}"
    assert isinstance(error.get("HTTPStatusCode"), int) and 400 <= error.get("HTTPStatusCode") < 500, f"{what}: expected HTTP 4xx, got {error!r}"
    assert error.get("Message") == expected_message, f'expected the message {expected_message!r}, got {error.get("Message")!r}'

def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """WebACL: create -> Get returns LockToken -> Update changes DefaultAction and rotates the
    token -> Delete succeeds -> Get is WAFNonexistentItemException, the listing drops it, and an
    update on the dead id is refused."""
    w = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-behav-waf-acl-")
    created = _retry_transient(
        lambda: w.create_web_acl(
            Name=name, Scope=SCOPE, DefaultAction={"Allow": {}}, Rules=[],
            VisibilityConfig=_visibility_config(name.replace("-", "")),
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", name, SCOPE, created["Id"]))

    got = w.get_web_acl(Name=name, Scope=SCOPE, Id=created["Id"])
    assert "Allow" in got["WebACL"]["DefaultAction"], (
        f"expected DefaultAction Allow after create, got {got['WebACL']['DefaultAction']!r}"
    )
    lock_token = got["LockToken"]

    updated = _retry_transient(
        lambda: w.update_web_acl(
            Name=name, Scope=SCOPE, Id=created["Id"], DefaultAction={"Block": {}}, Rules=[],
            VisibilityConfig=_visibility_config(name.replace("-", "")), LockToken=lock_token,
        )
    )
    assert updated["NextLockToken"] != lock_token, "LockToken must rotate on every mutation"

    got2 = w.get_web_acl(Name=name, Scope=SCOPE, Id=created["Id"])
    assert "Block" in got2["WebACL"]["DefaultAction"], (
        f"expected DefaultAction Block after update, got {got2['WebACL']['DefaultAction']!r}"
    )

    assert created["Id"] in _list_web_acl_ids(w, SCOPE), "the live WebACL must be listed before the delete"

    _retry_transient(
        lambda: w.delete_web_acl(
            Name=name, Scope=SCOPE, Id=created["Id"], LockToken=got2["LockToken"]
        )
    )

    error = _error_stable(
        lambda: w.get_web_acl(Name=name, Scope=SCOPE, Id=created["Id"])
    )
    _assert_nonexistent(error, "GetWebACL on the deleted id", expected_message="AWS WAF couldn’t perform the operation because your resource doesn’t exist.")

    assert created["Id"] not in _list_web_acl_ids(w, SCOPE), "the deleted WebACL is still listed"

    dead_update = _error_stable(
        lambda: w.update_web_acl(
            Name=name, Scope=SCOPE, Id=created["Id"], DefaultAction={"Allow": {}}, Rules=[],
            VisibilityConfig=_visibility_config(name.replace("-", "")), LockToken=got2["LockToken"],
        )
    )
    _assert_nonexistent(dead_update, "UpdateWebACL on the deleted id", expected_message="AWS WAF couldn’t perform the operation because your resource doesn’t exist.")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
