"""rate-based-statement-managed-keys-empty."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rate-based-statement-managed-keys-empty"
GROUP = 'traffic'
SERVICES = ['wafv2']


SCOPE = "REGIONAL"

#: WAFNonexistentItemException's message for a RuleName the WebACL does not have.
NONEXISTENT_MESSAGE = "AWS WAF couldn’t perform the operation because your resource doesn’t exist."

_TRANSIENT_CODES = frozenset(
    {"ThrottlingException", "WAFUnavailableEntityException", "WAFInternalErrorException",
     "WAFNonexistentItemException"}
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

def _create_web_acl(ctx, w, name=None, rules=None, default_action=None, scope=SCOPE):
    """Create a WebACL (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-acl-")
    created = _retry_transient(
        lambda: w.create_web_acl(
            Name=name, Scope=scope,
            DefaultAction=default_action or {"Allow": {}},
            Rules=rules or [],
            VisibilityConfig=_visibility_config(name.replace("-", "")),
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", name, scope, created["Id"]))
    return created

def _rate_based_rule(name, limit, priority=0):
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {"RateBasedStatement": {"Limit": limit, "AggregateKeyType": "IP"}},
        "Action": {"Block": {}},
        "VisibilityConfig": _visibility_config(name.replace("-", "")),
    }

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetRateBasedStatementManagedKeys on an idle rate-based rule returns empty key lists, while
    a RuleName not on the WebACL is rejected, so an idle rule is told apart from an unknown name."""
    w = ctx.client("wafv2")
    rule = _rate_based_rule("rate-limit-ip", limit=100, priority=0)
    summary = _create_web_acl(ctx, w, rules=[rule])

    resp = _retry_transient(
        lambda: w.get_rate_based_statement_managed_keys(
            Scope=SCOPE,
            WebACLName=summary["Name"],
            WebACLId=summary["Id"],
            RuleName="rate-limit-ip",
        )
    )
    assert resp["ManagedKeysIPV4"]["Addresses"] == [], resp["ManagedKeysIPV4"]
    assert resp["ManagedKeysIPV6"]["Addresses"] == [], resp["ManagedKeysIPV6"]

    try:
        w.get_rate_based_statement_managed_keys(
            Scope=SCOPE,
            WebACLName=summary["Name"],
            WebACLId=summary["Id"],
            RuleName="does-not-exist-on-this-acl",
        )
        raise AssertionError(
            "expected WAFNonexistentItemException for a RuleName not on the WebACL"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "WAFNonexistentItemException", (
            f"expected WAFNonexistentItemException for an unknown RuleName, got {code!r}"
        )
        assert exc.response["Error"]["Message"] == NONEXISTENT_MESSAGE, exc.response["Error"]

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
