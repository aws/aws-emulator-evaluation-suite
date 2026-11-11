"""check-capacity-text-transformation-wcu-delta."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "check-capacity-text-transformation-wcu-delta"
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


def _byte_match(field, transforms, constraint="STARTS_WITH"):
    return {
        "ByteMatchStatement": {
            "SearchString": b"/wp-login.php",
            "FieldToMatch": field,
            "TextTransformations": transforms,
            "PositionalConstraint": constraint,
        }
    }


def _transforms(*types):
    return [{"Priority": i, "Type": t} for i, t in enumerate(types)]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CheckCapacity adds the documented modifiers to a STARTS_WITH byte match (2 WCU): +10 per text
    transformation, +10 for all query parameters, and double the base cost for the JSON body.
    """
    w = ctx.client("wafv2")
    uri = {"UriPath": {}}

    # Baseline: STARTS_WITH byte match on UriPath with the single NONE transformation.
    base = _wcu(w, _byte_match(uri, _transforms("NONE")))
    assert base == 2, f"STARTS_WITH byte match base cost is 2 WCU, got {base}"

    # "For each Text transformation that you apply, add 10 WCUs." NONE is the no-op
    # placeholder and adds 0; each real transformation adds exactly 10.
    one = _wcu(w, _byte_match(uri, _transforms("LOWERCASE")))
    assert one - base == 10, (
        f"one LOWERCASE transformation must add exactly 10 WCU, got {one - base} "
        f"(base={base}, one={one})"
    )

    two = _wcu(w, _byte_match(uri, _transforms("LOWERCASE", "URL_DECODE")))
    assert two - base == 20, (
        f"two transformations must add exactly 20 WCU, got {two - base} "
        f"(base={base}, two={two})"
    )

    three = _wcu(w, _byte_match(uri, _transforms("LOWERCASE", "URL_DECODE", "COMPRESS_WHITE_SPACE")))
    assert three - base == 30, (
        f"three transformations must add exactly 30 WCU, got {three - base} "
        f"(base={base}, three={three})"
    )
    # Strictly monotonic in the transformation count, with a constant step.
    assert [base, one, two, three] == [base, base + 10, base + 20, base + 30], \
        [base, one, two, three]

    # "If you use the request component All query parameters, add 10 WCUs."
    all_qs = _wcu(w, _byte_match({"AllQueryArguments": {}}, _transforms("NONE")))
    assert all_qs - base == 10, (
        f"AllQueryArguments must add exactly 10 WCU, got {all_qs - base} "
        f"(base={base}, all_query_args={all_qs})"
    )

    # "If you use the request component JSON body, double the base cost WCUs."
    json_body = _wcu(w, _byte_match(
        {"JsonBody": {"MatchPattern": {"All": {}}, "MatchScope": "ALL"}},
        _transforms("NONE"),
    ))
    assert json_body == 2 * base, (
        f"JsonBody must double the base cost to {2 * base} WCU, got {json_body}"
    )

    # The modifiers compose: JSON body doubles the base, then each transformation
    # still adds a flat 10 on top of the doubled base.
    json_one = _wcu(w, _byte_match(
        {"JsonBody": {"MatchPattern": {"All": {}}, "MatchScope": "ALL"}},
        _transforms("LOWERCASE"),
    ))
    assert json_one == 2 * base + 10, (
        f"JsonBody + one transformation must cost {2 * base + 10} WCU, got {json_one}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
