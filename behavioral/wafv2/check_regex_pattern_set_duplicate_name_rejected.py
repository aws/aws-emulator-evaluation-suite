"""regex-pattern-set-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "regex-pattern-set-duplicate-name-rejected"
GROUP = 'regexpatternset'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

#: WAFDuplicateItemException's message for a reused Name+Scope.
DUPLICATE_MESSAGE = (
    "AWS WAF couldn’t perform the operation because some resource in your request is a "
    "duplicate of an existing one."
)

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
    """Return (code, message) of the first NON-transient failure of fn.
    Transient WAFv2 codes are retried rather than reported, so an assertion about a
    semantic error is never polluted by throttling or propagation delay. A call that
    succeeds raises AssertionError: the caller expects a refusal."""
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            resp = getattr(exc, "response", None)
            if not isinstance(resp, dict):
                raise
            err = resp.get("Error", {})
            code = err.get("Code", "")
            if not code:
                raise
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                return code, err.get("Message", "")
            time.sleep(delay)
            continue
        raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")
    raise AssertionError("unreachable: every attempt returns or raises")

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

def _create_regex_pattern_set(ctx, w, name=None, patterns=None, scope=SCOPE):
    """Create a RegexPatternSet (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-rps-")
    regex_list = [{"RegexString": p} for p in (patterns or ["^foo.*"])]
    created = _retry_transient(
        lambda: w.create_regex_pattern_set(
            Name=name, Scope=scope, RegularExpressionList=regex_list,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "regex_pattern_set", name, scope, created["Id"]))
    return created

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
    """A second RegexPatternSet with the same Name+Scope fails as duplicate, leaving the
    original untouched and no second entity; once the original is deleted the identical
    call succeeds."""
    w = ctx.client("wafv2")
    summary = _create_regex_pattern_set(ctx, w)
    name = summary["Name"]
    dup_patterns = [{"RegexString": "^/other"}]

    code, message = _error_stable(
        lambda: w.create_regex_pattern_set(
            Name=name, Scope=SCOPE, RegularExpressionList=dup_patterns,
        )
    )
    assert code == "WAFDuplicateItemException", code
    assert message == DUPLICATE_MESSAGE, message

    # Effect absent: the rejected duplicate created no second entity, and the
    # original's own data is untouched by the rejected attempt.
    matching = [s for s in _list_all(w.list_regex_pattern_sets, "RegexPatternSets") if s["Name"] == name]
    assert len(matching) == 1 and matching[0]["Id"] == summary["Id"], matching
    unchanged = w.get_regex_pattern_set(Name=name, Scope=SCOPE, Id=summary["Id"])["RegexPatternSet"]
    assert unchanged["RegularExpressionList"] == [{"RegexString": "^foo.*"}], unchanged

    # Restore: the duplicate name is a state-forbids rejection, not an always-invalid
    # one — freeing the name by deleting the original must let the identical call
    # that was just rejected succeed.
    _delete_locked(w, "regex_pattern_set", name, SCOPE, summary["Id"])
    restored = _retry_transient(
        lambda: w.create_regex_pattern_set(
            Name=name, Scope=SCOPE, RegularExpressionList=dup_patterns,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "regex_pattern_set", name, SCOPE, restored["Id"]))
    reread = w.get_regex_pattern_set(Name=name, Scope=SCOPE, Id=restored["Id"])["RegexPatternSet"]
    assert reread["RegularExpressionList"] == dup_patterns, reread

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
