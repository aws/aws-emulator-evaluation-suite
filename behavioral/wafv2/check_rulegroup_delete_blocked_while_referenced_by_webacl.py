"""rulegroup-delete-blocked-while-referenced-by-webacl."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rulegroup-delete-blocked-while-referenced-by-webacl"
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

def _rulegroup_reference_statement(arn):
    return {"RuleGroupReferenceStatement": {"ARN": arn}}

def _create_rulegroup(ctx, w, name=None, capacity=100, rules=None, scope=SCOPE):
    """Create a RuleGroup (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-rg-")
    summary = _retry_transient(
        lambda: w.create_rule_group(
            Name=name, Scope=scope, Capacity=capacity, Rules=rules or [],
            VisibilityConfig=_visibility_config(name.replace("-", "")[:128]),
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "rule_group", name, scope, summary["Id"]))
    return summary

def _create_webacl(ctx, w, name=None, rules=None, scope=SCOPE, default_allow=True):
    """Create a WebACL (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-acl-")
    summary = _retry_transient(
        lambda: w.create_web_acl(
            Name=name, Scope=scope,
            DefaultAction={"Allow": {}} if default_allow else {"Block": {}},
            Rules=rules or [],
            VisibilityConfig=_visibility_config(name.replace("-", "")[:128]),
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", name, scope, summary["Id"]))
    return summary


_NOT_FOUND_MESSAGE = "AWS WAF couldn\u2019t perform the operation because your resource doesn\u2019t exist."
_ASSOCIATED_MESSAGE = (
    "AWS WAF couldn\u2019t perform the operation because your resource is being used by "
    "another resource or it\u2019s associated with another resource."
)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRuleGroup on a group still referenced by a WebACL Rule must fail
    with WAFAssociatedItemException until the WebACL stops referencing it."""
    w = ctx.client("wafv2")
    rg = _create_rulegroup(ctx, w, capacity=50)
    webacl_name = ctx.unique_name("sim2real-behav-waf-acl-")
    rules = [
        {
            "Name": "use-rulegroup",
            "Priority": 0,
            "OverrideAction": {"None": {}},
            "Statement": _rulegroup_reference_statement(rg["ARN"]),
            "VisibilityConfig": _visibility_config("userulegroup"),
        }
    ]
    webacl = _create_webacl(ctx, w, name=webacl_name, rules=rules)

    rg_got = w.get_rule_group(Name=rg["Name"], Scope=SCOPE, Id=rg["Id"])
    code, message = _error_stable(
        lambda: w.delete_rule_group(
            Name=rg["Name"], Scope=SCOPE, Id=rg["Id"], LockToken=rg_got["LockToken"]
        )
    )
    assert code == "WAFAssociatedItemException", code
    assert message == _ASSOCIATED_MESSAGE, message

    # the rejected delete must not have removed the rule group (independent read)
    survived = _retry_transient(
        lambda: w.get_rule_group(Name=rg["Name"], Scope=SCOPE, Id=rg["Id"])
    )
    assert survived["RuleGroup"]["Id"] == rg["Id"], (
        f"rule group missing after rejected delete: {survived}"
    )

    acl_got = w.get_web_acl(Name=webacl["Name"], Scope=SCOPE, Id=webacl["Id"])
    _retry_transient(
        lambda: w.update_web_acl(
            Name=webacl["Name"], Scope=SCOPE, Id=webacl["Id"],
            DefaultAction={"Allow": {}}, Rules=[],
            VisibilityConfig=_visibility_config(webacl_name.replace("-", "")),
            LockToken=acl_got["LockToken"],
        )
    )

    # positive control: reference removed, the identical delete now succeeds
    rg_got2 = w.get_rule_group(Name=rg["Name"], Scope=SCOPE, Id=rg["Id"])
    _retry_transient(
        lambda: w.delete_rule_group(
            Name=rg["Name"], Scope=SCOPE, Id=rg["Id"], LockToken=rg_got2["LockToken"]
        )
    )

    # gone and unusable: an independent read returns the specific not-found code
    dead_read_code, dead_read_message = _error_stable(
        lambda: w.get_rule_group(Name=rg["Name"], Scope=SCOPE, Id=rg["Id"])
    )
    assert dead_read_code == "WAFNonexistentItemException", (
        f"expected WAFNonexistentItemException reading a deleted rule group, got {dead_read_code}"
    )
    assert dead_read_message == _NOT_FOUND_MESSAGE, dead_read_message

    # a mutation on the now-dead id also fails, not just a read
    dead_delete_code, dead_delete_message = _error_stable(
        lambda: w.delete_rule_group(
            Name=rg["Name"], Scope=SCOPE, Id=rg["Id"], LockToken=rg_got2["LockToken"]
        )
    )
    assert dead_delete_code == "WAFNonexistentItemException", (
        f"expected WAFNonexistentItemException deleting an already-deleted rule group, "
        f"got {dead_delete_code}"
    )
    assert dead_delete_message == _NOT_FOUND_MESSAGE, dead_delete_message

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
