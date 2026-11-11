"""rulegroup-lifecycle-with-ipset-reference."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rulegroup-lifecycle-with-ipset-reference"
GROUP = 'rulegroup'
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

def _delete_locked(w, kind, name, scope, id_):
    """Refresh the LockToken then delete (WAFv2 delete_* require the current token). Already
    gone is clean; a reference still being released or a transient error is retried for 15 s."""
    getter = getattr(w, f"get_{kind}")
    deleter = getattr(w, f"delete_{kind}")
    retryable = _TRANSIENT_CODES | {"WAFAssociatedItemException", "WAFOptimisticLockException"}
    deadline = time.monotonic() + 15.0
    while True:
        try:
            lt = getter(Name=name, Scope=scope, Id=id_)["LockToken"]
            deleter(Name=name, Scope=scope, Id=id_, LockToken=lt)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "WAFNonexistentItemException":
                return
            if code not in retryable or time.monotonic() >= deadline:
                raise
        time.sleep(2)

def _visibility_config(metric_name):
    return {"SampledRequestsEnabled": True, "CloudWatchMetricsEnabled": True,
            "MetricName": metric_name}

def _ipset_reference_statement(arn):
    return {"IPSetReferenceStatement": {"ARN": arn}}

def _create_ipset(ctx, w, name=None, addresses=None, scope=SCOPE):
    """Create an IPSet (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-ips-")
    addresses = addresses if addresses is not None else ["10.0.0.0/8"]
    summary = _retry_transient(
        lambda: w.create_ip_set(
            Name=name, Scope=scope, IPAddressVersion="IPV4", Addresses=addresses
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "ip_set", name, scope, summary["Id"]))
    return summary


_NOT_FOUND_MESSAGE = "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RuleGroup created with a Rule containing an IPSetReferenceStatement
    round-trips the real statement through GetRuleGroup, and UpdateRuleGroup
    can swap in a different rule set while rotating LockToken."""
    w = ctx.client("wafv2")
    ipset = _create_ipset(ctx, w, addresses=["198.51.100.0/24"])
    rg_name = ctx.unique_name("sim2real-behav-waf-rg-")
    rules = [
        {
            "Name": "match-ipset",
            "Priority": 0,
            "Statement": _ipset_reference_statement(ipset["ARN"]),
            "Action": {"Count": {}},
            "VisibilityConfig": _visibility_config("matchipset"),
        }
    ]
    created = _retry_transient(
        lambda: w.create_rule_group(
            Name=rg_name, Scope=SCOPE, Capacity=25, Rules=rules,
            VisibilityConfig=_visibility_config(rg_name.replace("-", "")),
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "rule_group", rg_name, SCOPE, created["Id"]))

    got = w.get_rule_group(Name=rg_name, Scope=SCOPE, Id=created["Id"])
    assert len(got["RuleGroup"]["Rules"]) == 1, f"expected 1 rule, got {got['RuleGroup']['Rules']!r}"
    stmt = got["RuleGroup"]["Rules"][0]["Statement"]
    assert stmt["IPSetReferenceStatement"]["ARN"] == ipset["ARN"], (
        f"expected IPSetReferenceStatement ARN {ipset['ARN']!r}, got {stmt!r}"
    )
    lock_token = got["LockToken"]

    updated = _retry_transient(
        lambda: w.update_rule_group(
            Name=rg_name, Scope=SCOPE, Id=created["Id"], Rules=[],
            VisibilityConfig=_visibility_config(rg_name.replace("-", "")),
            LockToken=lock_token,
        )
    )
    assert updated["NextLockToken"] != lock_token, "LockToken must rotate on every mutation"

    got2 = w.get_rule_group(Name=rg_name, Scope=SCOPE, Id=created["Id"])
    assert got2["RuleGroup"]["Rules"] == [], f"expected rules cleared, got {got2['RuleGroup']['Rules']!r}"
    assert got2["RuleGroup"]["Capacity"] == 25, f"expected Capacity 25, got {got2['RuleGroup']['Capacity']!r}"

    _retry_transient(
        lambda: w.delete_rule_group(
            Name=rg_name, Scope=SCOPE, Id=created["Id"], LockToken=got2["LockToken"]
        )
    )

    code, message = _error_stable(
        lambda: w.get_rule_group(Name=rg_name, Scope=SCOPE, Id=created["Id"])
    )
    assert code == "WAFNonexistentItemException", (
        f"expected GetRuleGroup on the deleted rule group to fail with "
        f"WAFNonexistentItemException, got {code!r}"
    )
    assert message == _NOT_FOUND_MESSAGE, message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
