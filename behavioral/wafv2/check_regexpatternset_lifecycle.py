"""regexpatternset-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "regexpatternset-lifecycle"
GROUP = 'regexpatternset'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

#: WAFNonexistentItemException's message for a deleted regex pattern set.
NONEXISTENT_MESSAGE = "AWS WAF couldn’t perform the operation because your resource doesn’t exist."

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


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegexPatternSet: create -> Get returns LockToken -> Update replaces
    the pattern list and rotates the token -> Delete succeeds."""
    w = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-behav-waf-rps-")
    created = _retry_transient(
        lambda: w.create_regex_pattern_set(
            Name=name, Scope=SCOPE, RegularExpressionList=[{"RegexString": "^foo.*"}],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "regex_pattern_set", name, SCOPE, created["Id"]))

    got = w.get_regex_pattern_set(Name=name, Scope=SCOPE, Id=created["Id"])
    assert got["RegexPatternSet"]["RegularExpressionList"] == [{"RegexString": "^foo.*"}], (
        f"expected [^foo.*] right after create, got {got['RegexPatternSet']['RegularExpressionList']}"
    )
    lock_token = got["LockToken"]

    updated = _retry_transient(
        lambda: w.update_regex_pattern_set(
            Name=name, Scope=SCOPE, Id=created["Id"],
            RegularExpressionList=[{"RegexString": "^bar.*"}, {"RegexString": "^baz.*"}],
            LockToken=lock_token,
        )
    )
    assert updated["NextLockToken"] != lock_token, (
        f"expected update to rotate the LockToken away from {lock_token}, "
        f"got the same value back: {updated['NextLockToken']}"
    )

    got2 = w.get_regex_pattern_set(Name=name, Scope=SCOPE, Id=created["Id"])
    patterns = {p["RegexString"] for p in got2["RegexPatternSet"]["RegularExpressionList"]}
    assert patterns == {"^bar.*", "^baz.*"}, (
        f"expected the update to fully replace the pattern list with {{^bar.*, ^baz.*}}, "
        f"got {patterns}"
    )

    _retry_transient(
        lambda: w.delete_regex_pattern_set(
            Name=name, Scope=SCOPE, Id=created["Id"], LockToken=got2["LockToken"]
        )
    )

    code, message = _error_stable(
        lambda: w.get_regex_pattern_set(Name=name, Scope=SCOPE, Id=created["Id"])
    )
    assert code == "WAFNonexistentItemException", (
        f"expected GetRegexPatternSet on the deleted id to raise WAFNonexistentItemException, "
        f"got {code!r}"
    )
    assert message == NONEXISTENT_MESSAGE, message

    mutate_code, mutate_message = _error_stable(
        lambda: w.update_regex_pattern_set(
            Name=name, Scope=SCOPE, Id=created["Id"],
            RegularExpressionList=[{"RegexString": "^qux.*"}],
            LockToken=got2["LockToken"],
        )
    )
    assert mutate_code == "WAFNonexistentItemException", (
        f"expected UpdateRegexPatternSet on the deleted id to also raise "
        f"WAFNonexistentItemException, got {mutate_code!r}"
    )
    assert mutate_message == NONEXISTENT_MESSAGE, mutate_message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
