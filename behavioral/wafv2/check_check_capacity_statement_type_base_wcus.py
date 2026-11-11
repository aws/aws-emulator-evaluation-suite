"""check-capacity-statement-type-base-wcus."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "check-capacity-statement-type-base-wcus"
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
    """Wrap a single statement in the minimal legal regular Rule."""
    return {
        "Name": name,
        "Priority": priority,
        "Statement": statement,
        "Action": {"Count": {}},
        "VisibilityConfig": _visibility_config(name.replace("-", "")),
    }


def _uri_path():
    """UriPath: the only request component with NO WCU adder (query params add 10,
    JSON body doubles the base cost)."""
    return {"UriPath": {}}


def _no_transform():
    """The single required NONE transformation, which adds 0 WCU."""
    return [{"Priority": 0, "Type": "NONE"}]


def _wcu(w, statement):
    """The WCU cost of exactly one rule carrying this statement."""
    return _retry_transient(
        lambda: w.check_capacity(Scope=SCOPE, Rules=[_rule(statement)])
    )["Capacity"]


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CheckCapacity returns the documented base WCU per statement type: size, geo and label 1, byte
    match 2 (EXACTLY, STARTS_WITH, ENDS_WITH) or 10 (CONTAINS, CONTAINS_WORD), regex 3, SQLi 20
    (LOW) or 30 (HIGH), XSS 40.
    """
    w = ctx.client("wafv2")
    tt = _no_transform()
    fm = _uri_path()

    # Size constraint rule statement: "1 WCU, as a base cost."
    size = _wcu(w, {
        "SizeConstraintStatement": {
            "FieldToMatch": fm, "ComparisonOperator": "GT", "Size": 1024,
            "TextTransformations": tt,
        }
    })
    assert size == 1, f"SizeConstraintStatement base cost is 1 WCU, got {size}"

    # Geographic match: WCUs column = 1.
    geo = _wcu(w, {"GeoMatchStatement": {"CountryCodes": ["US", "CA"]}})
    assert geo == 1, f"GeoMatchStatement base cost is 1 WCU, got {geo}"

    # Label match rule statement: WCUs column = 1.
    label = _wcu(w, {"LabelMatchStatement": {"Scope": "LABEL", "Key": "probe:seen"}})
    assert label == 1, f"LabelMatchStatement base cost is 1 WCU, got {label}"

    # String match rule statement: "Exactly matches string - 2 / Starts with string - 2
    # / Ends with string - 2 / Contains string - 10 / Contains word - 10".
    byte_costs = {}
    for constraint in ("EXACTLY", "STARTS_WITH", "ENDS_WITH", "CONTAINS", "CONTAINS_WORD"):
        byte_costs[constraint] = _wcu(w, {
            "ByteMatchStatement": {
                "SearchString": b"admin", "FieldToMatch": fm,
                "TextTransformations": tt, "PositionalConstraint": constraint,
            }
        })
    assert byte_costs["EXACTLY"] == 2, byte_costs
    assert byte_costs["STARTS_WITH"] == 2, byte_costs
    assert byte_costs["ENDS_WITH"] == 2, byte_costs
    assert byte_costs["CONTAINS"] == 10, byte_costs
    assert byte_costs["CONTAINS_WORD"] == 10, byte_costs

    # Regex match rule statement: "3 WCUs, as a base cost."
    regex = _wcu(w, {
        "RegexMatchStatement": {
            "RegexString": "^/admin", "FieldToMatch": fm, "TextTransformations": tt,
        }
    })
    assert regex == 3, f"RegexMatchStatement base cost is 3 WCU, got {regex}"

    # SQL injection attack rule statement: "Low costs 20 and High costs 30."
    sqli_low = _wcu(w, {
        "SqliMatchStatement": {
            "FieldToMatch": fm, "TextTransformations": tt, "SensitivityLevel": "LOW",
        }
    })
    sqli_high = _wcu(w, {
        "SqliMatchStatement": {
            "FieldToMatch": fm, "TextTransformations": tt, "SensitivityLevel": "HIGH",
        }
    })
    assert sqli_low == 20, f"SqliMatchStatement LOW base cost is 20 WCU, got {sqli_low}"
    assert sqli_high == 30, f"SqliMatchStatement HIGH base cost is 30 WCU, got {sqli_high}"
    assert sqli_high - sqli_low == 10, (sqli_low, sqli_high)

    # Cross-site scripting attack rule statement: "40 WCUs, as a base cost."
    xss = _wcu(w, {
        "XssMatchStatement": {"FieldToMatch": fm, "TextTransformations": tt}
    })
    assert xss == 40, f"XssMatchStatement base cost is 40 WCU, got {xss}"

    # The costs must be genuinely type-sensitive, not one constant with noise: five
    # distinct values across the eight statement types above.
    distinct = {size, geo, label, byte_costs["EXACTLY"], byte_costs["CONTAINS"],
                regex, sqli_low, sqli_high, xss}
    assert len(distinct) >= 5, (
        f"CheckCapacity returned only {len(distinct)} distinct costs across 8 statement "
        f"types ({sorted(distinct)}) -- the cost model is not statement-type sensitive"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
