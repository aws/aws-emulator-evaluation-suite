"""check-capacity-nested-logical-statement-composition."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "check-capacity-nested-logical-statement-composition"
GROUP = 'capacity'
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


def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}


def _rule(statement, name="probe", priority=0):
    return {
        "Name": name,
        "Priority": priority,
        "Statement": statement,
        "Action": {"Count": {}},
        "VisibilityConfig": _visibility_config(name.replace("-", "")),
    }


def _wcu(w, statement):
    return _retry_transient(
        lambda: w.check_capacity(Scope=SCOPE, Rules=[_rule(statement)])
    )["Capacity"]

# Leaf statements, deliberately of DIFFERENT types on DIFFERENT request components.
# The WCU doc warns that WAF may discount siblings that "examine the same web request
# component" with the same transformation, so identical leaves would make exact
# additivity unsound. These four cannot be combined, so the sum is exact.
_GEO = {"GeoMatchStatement": {"CountryCodes": ["US"]}}                              # 1
_SIZE = {"SizeConstraintStatement": {                                              # 1
    "FieldToMatch": {"UriPath": {}}, "ComparisonOperator": "GT", "Size": 8192,
    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
}}
_REGEX = {"RegexMatchStatement": {                                                 # 3
    "RegexString": "^/admin", "FieldToMatch": {"SingleHeader": {"Name": "referer"}},
    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
}}
_XSS = {"XssMatchStatement": {                                                     # 40
    "FieldToMatch": {"QueryString": {}},
    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
}}


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CheckCapacity costs And, Or and Not statements from their nested statements: geo, size, regex
    and XSS cost 1, 1, 3 and 40 WCU, Not(XSS) equals XSS, and And/Or totals equal the sums of their
    nested statements at every depth.
    """
    w = ctx.client("wafv2")

    geo = _wcu(w, _GEO)
    size = _wcu(w, _SIZE)
    regex = _wcu(w, _REGEX)
    xss = _wcu(w, _XSS)
    assert (geo, size, regex, xss) == (1, 1, 3, 40), (
        f"leaf premise broken: geo={geo} size={size} regex={regex} xss={xss}; "
        "expected the published base costs 1/1/3/40"
    )

    # NOT negates one nested statement and adds nothing of its own.
    not_xss = _wcu(w, {"NotStatement": {"Statement": _XSS}})
    assert not_xss == xss, (
        f"NotStatement cost must equal its single nested statement ({xss}), got {not_xss}"
    )

    # AND over two non-combinable leaves == the sum of the leaves.
    and_2 = _wcu(w, {"AndStatement": {"Statements": [_GEO, _XSS]}})
    assert and_2 == geo + xss, (
        f"AndStatement(geo,xss) must cost {geo + xss}, got {and_2}"
    )

    # OR over the same two leaves costs the same as AND: the operator is free, only
    # the tree matters.
    or_2 = _wcu(w, {"OrStatement": {"Statements": [_GEO, _XSS]}})
    assert or_2 == and_2, (
        f"OrStatement and AndStatement over the same leaves must cost the same; "
        f"or={or_2} and={and_2}"
    )

    # AND over four distinct leaves == the sum of all four.
    and_4 = _wcu(w, {"AndStatement": {"Statements": [_GEO, _SIZE, _REGEX, _XSS]}})
    assert and_4 == geo + size + regex + xss, (
        f"AndStatement over 4 distinct leaves must cost {geo + size + regex + xss}, "
        f"got {and_4}"
    )

    # Two levels of nesting: OR( geo, NOT( AND(regex, xss) ) ). Recursion is required;
    # a one-level walk sees only the two direct children.
    deep = _wcu(w, {
        "OrStatement": {
            "Statements": [
                _GEO,
                {"NotStatement": {
                    "Statement": {"AndStatement": {"Statements": [_REGEX, _XSS]}}
                }},
            ]
        }
    })
    assert deep == geo + regex + xss, (
        f"OR(geo, NOT(AND(regex,xss))) must cost {geo + regex + xss}, got {deep}"
    )
    # A deeper tree over a strict superset of leaves must cost strictly more than the
    # shallower one -- a monotonicity property no constant model can satisfy.
    assert and_4 > and_2 > geo, (and_4, and_2, geo)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
