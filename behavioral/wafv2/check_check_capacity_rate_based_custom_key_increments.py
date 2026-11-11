"""check-capacity-rate-based-custom-key-increments."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "check-capacity-rate-based-custom-key-increments"
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
        "Action": {"Block": {}},
        "VisibilityConfig": _visibility_config(name.replace("-", "")),
    }


def _wcu(w, statement):
    return _retry_transient(
        lambda: w.check_capacity(Scope=SCOPE, Rules=[_rule(statement)])
    )["Capacity"]


def _rate_based(custom_keys=None, scope_down=None, limit=2000):
    stmt = {"Limit": limit}
    if custom_keys is None:
        stmt["AggregateKeyType"] = "IP"
    else:
        stmt["AggregateKeyType"] = "CUSTOM_KEYS"
        stmt["CustomKeys"] = custom_keys
    if scope_down is not None:
        stmt["ScopeDownStatement"] = scope_down
    return {"RateBasedStatement": stmt}


@tags("axis:happy-path", "cap:c7", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CheckCapacity costs a rate-based statement 2 WCU for AggregateKeyType IP and 32, 62 and 92
    WCU for one, two and three custom keys (+30 each), plus the cost of a scope-down statement (XSS,
    40 WCU).
    """
    w = ctx.client("wafv2")

    by_ip = _wcu(w, _rate_based())
    assert by_ip == 2, f"RateBasedStatement(AggregateKeyType=IP) is 2 WCU, got {by_ip}"

    one_key = _wcu(w, _rate_based([{"HTTPMethod": {}}]))
    assert one_key == 32, (
        f"one custom aggregation key must add 30 to the 2 WCU base (=32), got {one_key}"
    )
    assert one_key - by_ip == 30, (by_ip, one_key)

    two_keys = _wcu(w, _rate_based([
        {"IP": {}},
        {"Cookie": {"Name": "session", "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}},
    ]))
    assert two_keys == 62, (
        f"two custom aggregation keys must cost 2 + 2*30 = 62 WCU, got {two_keys}"
    )

    three_keys = _wcu(w, _rate_based([
        {"IP": {}},
        {"Cookie": {"Name": "session", "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}},
        {"Header": {"Name": "x-api-client",
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}]}},
    ]))
    assert three_keys == 92, (
        f"three custom aggregation keys must cost 2 + 3*30 = 92 WCU, got {three_keys}"
    )

    # The increment is exactly 30 per key and constant across key counts.
    assert [one_key, two_keys, three_keys] == [32, 62, 92], \
        [one_key, two_keys, three_keys]
    assert two_keys - one_key == 30 and three_keys - two_keys == 30, \
        (one_key, two_keys, three_keys)

    # A scope-down statement's own cost is added on top of the rate-based cost.
    # XssMatchStatement is 40 WCU as a base, so IP-aggregated + scope-down == 42.
    xss = {"XssMatchStatement": {
        "FieldToMatch": {"QueryString": {}},
        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
    }}
    xss_alone = _wcu(w, xss)
    assert xss_alone == 40, f"XssMatchStatement base cost is 40 WCU, got {xss_alone}"
    with_scope_down = _wcu(w, _rate_based(scope_down=xss))
    assert with_scope_down == by_ip + xss_alone, (
        f"rate-based + scope-down must cost {by_ip + xss_alone} "
        f"(2 base + 40 nested), got {with_scope_down}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
