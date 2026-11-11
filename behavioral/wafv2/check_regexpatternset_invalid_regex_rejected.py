"""regexpatternset-invalid-regex-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "regexpatternset-invalid-regex-rejected"
GROUP = 'regexpatternset'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException"}
)

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
    """CreateRegexPatternSet rejects an invalid regular expression with WAFInvalidParameterException and
    the exact REGEX_PATTERN_SET message and lists nothing under that name; the same call with a valid
    pattern succeeds and is listed.
    """
    w = ctx.client("wafv2")
    ctrl_name = ctx.unique_name("sim2real-behav-waf-rps-ctrl-")
    w.create_regex_pattern_set(
        Name=ctrl_name, Scope=SCOPE, RegularExpressionList=[{"RegexString": "^[a-z]+$"}],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    listed = _list_all(w.list_regex_pattern_sets, "RegexPatternSets")
    ctrl_summary = next((s for s in listed if s["Name"] == ctrl_name), None)
    assert ctrl_summary is not None, "positive control not visible via ListRegexPatternSets"
    ctx.on_cleanup(lambda: w.delete_regex_pattern_set(
        Name=ctrl_name, Scope=SCOPE, Id=ctrl_summary["Id"],
        LockToken=w.get_regex_pattern_set(Name=ctrl_name, Scope=SCOPE, Id=ctrl_summary["Id"])["LockToken"],
    ))

    name = ctx.unique_name("sim2real-behav-waf-rps-")
    code, message = _error_stable(
        lambda: w.create_regex_pattern_set(
            Name=name, Scope=SCOPE, RegularExpressionList=[{"RegexString": "("}]
        )
    )
    assert code == "WAFInvalidParameterException", code
    assert message == (
        "Error reason: The parameter contains formatting that is not valid., "
        "field: REGEX_PATTERN_SET, parameter: ("
    ), message

    listed = _list_all(w.list_regex_pattern_sets, "RegexPatternSets")
    assert not any(s["Name"] == name for s in listed), (
        f"rejected create must not appear in ListRegexPatternSets: {name}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
