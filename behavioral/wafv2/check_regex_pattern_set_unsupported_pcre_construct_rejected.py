"""regex-pattern-set-unsupported-pcre-construct-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "regex-pattern-set-unsupported-pcre-construct-rejected"
GROUP = 'overly-permissive'
SERVICES = ['wafv2']


# ===== helpers =====

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


def _error_code(fn):
    """Run fn, expecting failure; return (code, response). A call that succeeds raises
    AssertionError: the caller expects a refusal."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - the error IS the assertion target
        resp = getattr(exc, "response", None)
        if not isinstance(resp, dict):
            raise
        return resp.get("Error", {}).get("Code", ""), resp
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


def _delete_locked(w, kind, name, scope, id_):
    """Delete a WAFv2 resource, ALWAYS re-fetching its LockToken inside this call.

    A LockToken captured at create time is invalidated by every intervening update, and
    deleting with a stale token fails with WAFOptimisticLockException -- which means the
    resource survives.
    """
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    cur = _retry_transient(lambda: getter(Name=name, Scope=scope, Id=id_))
    token = cur["LockToken"]
    _retry_transient(
        lambda: deleter(Name=name, Scope=scope, Id=id_, LockToken=token),
        codes=_TRANSIENT_CODES | {"WAFAssociatedItemException"},
    )
# ===== end helpers =====

# AWS WAF's write-time validator enforces its regex flavour rather than accepting and never
# matching, and its verdicts do not line up with the documentation on either side, so both
# tuples below are write-time verdicts rather than doc citations.

# Constructs Create/UpdateRegexPatternSet ACCEPTS. The last two are the surprise: AWS documents
# capturing subexpressions and the \C single-byte directive as unsupported by the matching
# engine, yet the validator takes them. That is exactly the docs-versus-API gap this check
# exists to pin -- an emulator built from the documentation refuses writes real AWS accepts.
_ACCEPTED_AT_WRITE = (
    r"(?:admin|root)",              # non-capturing group
    r"^/api/v[0-9]{1,3}/",          # bounded quantifier + character class
    r"(?i)wp-login\.php",           # inline flag
    r"[[:alpha:]]+",                # POSIX character class
    r"(abc)",                       # capturing group: documented unsupported, ACCEPTED
    r"\C",                          # single-byte directive: documented unsupported, ACCEPTED
)

# Constructs it REFUSES, every one with WAFInvalidParameterException / Field REGEX_PATTERN_SET
# / Reason "The parameter contains formatting that is not valid." and Parameter echoing the
# offending pattern.
#
# AWS WAF refuses all three lookaround forms (positive/negative lookahead, lookbehind), which
# Python's `re` accepts -- so a re-backed emulator is permissive on the entire
# zero-width-assertion class.
_REFUSED_AT_WRITE = (
    r"(?=.*password)",  # lookahead: VALID in Python re, refused by AWS WAF
    r"(?!x)admin",      # negative lookahead: VALID in Python re, refused by AWS WAF
    r"(?<=/)admin",     # lookbehind: VALID in Python re, refused by AWS WAF
    r"(a)\1",           # backreference: VALID in Python re, refused by AWS WAF
    r"(?>abc)",         # atomic group: VALID in Python 3.11+ re, refused by AWS WAF
    r"a++",             # possessive quantifier
    r"foo\Kbar",        # \K start-of-match reset
    r"(?R)x",           # recursive pattern / subroutine reference
    r"\R",              # any-newline match
    r"(?(1)a|b)",       # conditional pattern
    r"(*FAIL)",         # backtracking control verb
)

# The refusal's structured fields, identical for every construct above.
_REFUSAL_FIELD = "REGEX_PATTERN_SET"
_REFUSAL_REASON = "The parameter contains formatting that is not valid."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Create/UpdateRegexPatternSet enforce AWS WAF's regex flavour at write time: each refused
    construct is rejected down to its Field/Reason/Parameter with the stored set and LockToken
    unchanged, while the accepted constructs create and update.
    """
    w = ctx.client("wafv2")

    # ---- setup: every documented-supported construct is accepted together.
    set_name = ctx.unique_name("sim2real-behav-waf-rps-")[:128]
    created = _retry_transient(lambda: w.create_regex_pattern_set(
        Name=set_name, Scope=SCOPE, Description="pcre flavour probe",
        RegularExpressionList=[{"RegexString": s} for s in _ACCEPTED_AT_WRITE],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    ))["Summary"]
    ctx.on_cleanup(
        lambda: _delete_locked(w, "regex_pattern_set", set_name, SCOPE, created["Id"])
    )

    got = _retry_transient(
        lambda: w.get_regex_pattern_set(Name=set_name, Scope=SCOPE, Id=created["Id"])
    )
    stored = [e["RegexString"] for e in got["RegexPatternSet"]["RegularExpressionList"]]
    assert stored == list(_ACCEPTED_AT_WRITE), (
        f"the accepted PCRE constructs must round-trip verbatim and in order; "
        f"stored={stored} expected={list(_ACCEPTED_AT_WRITE)}"
    )
    token = got["LockToken"]

    # ---- break exactly one thing, once per refused construct: the pattern list is
    # the accepted set plus this single refused pattern.
    for bad in _REFUSED_AT_WRITE:
        patterns = [{"RegexString": s} for s in _ACCEPTED_AT_WRITE] + [{"RegexString": bad}]
        # _retry_transient is INSIDE _error_code so a ThrottlingException is retried rather
        # than mistaken for the refusal being asserted.
        code, resp = _error_code(lambda p=patterns: _retry_transient(
            lambda: w.update_regex_pattern_set(
                Name=set_name, Scope=SCOPE, Id=created["Id"], LockToken=token,
                RegularExpressionList=p,
            )
        ))
        assert code == "WAFInvalidParameterException", (
            f"expected WAFInvalidParameterException for the refused construct {bad!r}, "
            f"got {code}: {resp.get('Error')}"
        )
        assert resp.get("ResponseMetadata", {}).get("HTTPStatusCode") == 400, (
            bad, resp.get("ResponseMetadata", {}).get("HTTPStatusCode")
        )
        # The refusal is STRUCTURED, not just prose: it names the field that failed, the
        # reason, and -- the part that proves the validator looked at the patterns rather
        # than the request -- the offending pattern itself, echoed exactly, singled out from
        # the six valid ones sent alongside it.
        assert resp.get("Field") == _REFUSAL_FIELD, (
            f"the refusal for {bad!r} must name Field {_REFUSAL_FIELD}, got "
            f"{resp.get('Field')!r}"
        )
        assert resp.get("Reason") == _REFUSAL_REASON, (
            f"unexpected Reason for {bad!r}: {resp.get('Reason')!r}"
        )
        assert resp.get("Parameter") == bad, (
            f"the refusal must echo the single offending pattern; expected {bad!r}, got "
            f"{resp.get('Parameter')!r}"
        )
        assert resp["Error"]["Message"] == (
            f"Error reason: {_REFUSAL_REASON}, field: {_REFUSAL_FIELD}, parameter: {bad}"
        ), f"unexpected message for {bad!r}: {resp['Error']['Message']!r}"

        # ---- the effect is absent, after each individual refusal: the stored pattern
        # list is untouched and the write did not happen.
        after = _retry_transient(
            lambda: w.get_regex_pattern_set(Name=set_name, Scope=SCOPE, Id=created["Id"])
        )
        after_patterns = [
            e["RegexString"] for e in after["RegexPatternSet"]["RegularExpressionList"]
        ]
        assert after_patterns == list(_ACCEPTED_AT_WRITE), (
            f"the refused update for {bad!r} still mutated the stored pattern list: "
            f"{after_patterns}"
        )
        assert after["LockToken"] == token, (
            f"the refused update for {bad!r} rotated the LockToken, so it was treated as "
            f"a successful write"
        )

    # ---- the effect is absent at the resource level too: no second set was conjured.
    names = [s["Name"] for s in _list_all(w.list_regex_pattern_sets, "RegexPatternSets")]
    assert names.count(set_name) == 1, (names.count(set_name), set_name)

    # ---- the control still works: the supported list plus one more supported construct
    # updates successfully, so the five refusals were about the constructs and not about
    # UpdateRegexPatternSet or the LockToken.
    ok = _retry_transient(lambda: w.update_regex_pattern_set(
        Name=set_name, Scope=SCOPE, Id=created["Id"], LockToken=token,
        RegularExpressionList=[{"RegexString": s} for s in _ACCEPTED_AT_WRITE]
        + [{"RegexString": r"\d{3}-\d{2}-\d{4}"}],
    ))
    assert ok["NextLockToken"] != token, ok["NextLockToken"]
    control = _retry_transient(
        lambda: w.get_regex_pattern_set(Name=set_name, Scope=SCOPE, Id=created["Id"])
    )
    control_patterns = [
        e["RegexString"] for e in control["RegexPatternSet"]["RegularExpressionList"]
    ]
    assert control_patterns == list(_ACCEPTED_AT_WRITE) + [r"\d{3}-\d{2}-\d{4}"], control_patterns


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
