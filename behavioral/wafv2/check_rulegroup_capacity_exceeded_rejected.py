"""rulegroup-capacity-exceeded-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rulegroup-capacity-exceeded-rejected"
GROUP = 'overly-permissive'
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
    """Return (code, message) of the first NON-transient failure; an unexpected success
    raises. Transient WAFv2 codes are retried rather than reported, so an assertion about
    a semantic error is never polluted by throttling or propagation delay."""
    for attempt in range(attempts):
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            resp = getattr(exc, "response", None)
            err = resp.get("Error", {}) if isinstance(resp, dict) else {}
            code = err.get("Code", "")
            if not code:
                raise
            if code not in _TRANSIENT_CODES or attempt == attempts - 1:
                return code, err.get("Message")
            time.sleep(delay)
            continue
        raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")
    raise AssertionError("unreachable: attempts must be positive")

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

def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}

def _cheap_rule(name, priority=0):
    """A GeoMatchStatement -- one of WAFv2's lowest-WCU statement types, used as
    an in-budget positive control (verified against real AWS's own check_capacity,
    not assumed: a ByteMatchStatement is 10 WCU and does not fit Capacity=2)."""
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
        "Action": {"Count": {}},
        "VisibilityConfig": _visibility_config(f"{name.replace('-', '')}"),
    }

def _sqli_statement(idx=0):
    """A SqliMatchStatement (deliberately expensive, ~20 WCU each); idx varies the
    inspected header so sibling statements are never byte-identical."""
    return {
        "SqliMatchStatement": {
            "FieldToMatch": {"SingleHeader": {"Name": f"x-probe-{idx}"}},
            "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
        }
    }

def _expensive_rules(n_rules, per_rule):
    """n_rules rules, each an OrStatement of per_rule Sqli statements (~n*per*20 WCU)."""
    rules = []
    for i in range(n_rules):
        if per_rule == 1:
            statement = _sqli_statement(i)
        else:
            statement = {
                "OrStatement": {
                    "Statements": [_sqli_statement(i * per_rule + j) for j in range(per_rule)]
                }
            }
        rules.append({
            "Name": f"expensive-{i}",
            "Priority": i,
            "Statement": statement,
            "Action": {"Count": {}},
            "VisibilityConfig": _visibility_config(f"expensive{i}"),
        })
    return rules


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateRuleGroup with Rules whose WCUs exceed the Capacity fixed at creation is rejected
    with WAFInvalidParameterException (not WAFLimitsExceededException) and leaves the group as
    the prior in-budget update (positive control) left it: capacity is not elastic."""
    w = ctx.client("wafv2")
    rg_name = ctx.unique_name("sim2real-behav-waf-rg-")
    created = _retry_transient(
        lambda: w.create_rule_group(
            Name=rg_name, Scope=SCOPE, Capacity=2, Rules=[],
            VisibilityConfig=_visibility_config(rg_name.replace("-", "")),
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "rule_group", rg_name, SCOPE, created["Id"]))

    got = w.get_rule_group(Name=rg_name, Scope=SCOPE, Id=created["Id"])

    cheap_rules = [_cheap_rule("cheap-0")]
    cheap_cost = _retry_transient(
        lambda: w.check_capacity(Scope=SCOPE, Rules=cheap_rules)
    )["Capacity"]
    assert cheap_cost <= 2, f"positive-control premise broken: cheap rule costs {cheap_cost} WCU"

    # Positive control: an in-budget update against the same rule group, same
    # wiring, must succeed -- proving UpdateRuleGroup is not simply refused
    # outright on this target.
    _retry_transient(
        lambda: w.update_rule_group(
            Name=rg_name, Scope=SCOPE, Id=created["Id"], Rules=cheap_rules,
            VisibilityConfig=_visibility_config(rg_name.replace("-", "")),
            LockToken=got["LockToken"],
        )
    )
    got_after_control = w.get_rule_group(Name=rg_name, Scope=SCOPE, Id=created["Id"])
    assert got_after_control["RuleGroup"]["Rules"] == cheap_rules
    assert got_after_control["LockToken"] != got["LockToken"]

    oversized_rules = _expensive_rules(n_rules=1, per_rule=3)
    needed = _retry_transient(
        lambda: w.check_capacity(Scope=SCOPE, Rules=oversized_rules)
    )["Capacity"]
    assert needed > 2, f"premise broken: rules only cost {needed} WCU"

    code, message = _error_stable(
        lambda: w.update_rule_group(
            Name=rg_name, Scope=SCOPE, Id=created["Id"], Rules=oversized_rules,
            VisibilityConfig=_visibility_config(rg_name.replace("-", "")),
            LockToken=got_after_control["LockToken"],
        )
    )
    assert code == "WAFInvalidParameterException", code
    assert message == (
        "Error reason: You exceeded the capacity limit for a rule group or web ACL., "
        f"field: RULE_GROUP, parameter: {needed}"
    ), message

    got2 = w.get_rule_group(Name=rg_name, Scope=SCOPE, Id=created["Id"])
    assert got2["RuleGroup"]["Rules"] == cheap_rules
    assert got2["RuleGroup"]["Capacity"] == 2
    assert got2["LockToken"] == got_after_control["LockToken"]

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
