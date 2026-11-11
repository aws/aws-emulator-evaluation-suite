"""list-regex-pattern-sets-membership."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-regex-pattern-sets-membership"
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

def _create_regex_pattern_set(ctx, w, name=None, patterns=None, scope=SCOPE):
    """Create a RegexPatternSet (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-rps-")
    regex_list = [{"RegexString": p} for p in (patterns or ["^foo.*"])]
    created = _retry_transient(
        lambda: w.create_regex_pattern_set(
            Name=name, Scope=scope, RegularExpressionList=regex_list,
            Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "regex_pattern_set", name, scope, created["Id"]))
    return created

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRegexPatternSets returns the created set with a matching Id/ARN, and
    stops returning it once the set is deleted (and the id becomes unusable)."""
    w = ctx.client("wafv2")
    summary = _create_regex_pattern_set(ctx, w)
    items = _list_all(w.list_regex_pattern_sets, "RegexPatternSets")
    match = [s for s in items if s["Name"] == summary["Name"]]
    assert len(match) == 1, f"expected 1 entry for {summary['Name']}, got {len(match)}"
    assert match[0]["Id"] == summary["Id"], f"Id mismatch: {match[0]['Id']} != {summary['Id']}"
    assert match[0]["ARN"] == summary["ARN"], f"ARN mismatch: {match[0]['ARN']} != {summary['ARN']}"

    lock_token = w.get_regex_pattern_set(
        Name=summary["Name"], Scope=SCOPE, Id=summary["Id"]
    )["LockToken"]
    _retry_transient(
        lambda: w.delete_regex_pattern_set(
            Name=summary["Name"], Scope=SCOPE, Id=summary["Id"], LockToken=lock_token
        )
    )

    items_after = _list_all(w.list_regex_pattern_sets, "RegexPatternSets")
    match_after = [s for s in items_after if s["Id"] == summary["Id"]]
    assert not match_after, f"deleted set {summary['Id']} still present in list: {match_after}"

    code, message = _error_stable(
        lambda: w.get_regex_pattern_set(Name=summary["Name"], Scope=SCOPE, Id=summary["Id"])
    )
    assert code == "WAFNonexistentItemException", (
        f"expected WAFNonexistentItemException reading the deleted set, got {code}"
    )
    assert message == _NOT_FOUND, message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
