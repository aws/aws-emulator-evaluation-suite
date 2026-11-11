"""webacl-managed-rule-group-reference."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "webacl-managed-rule-group-reference"
GROUP = 'webacl'
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

def _create_web_acl(ctx, w, name=None, rules=None, default_action=None, scope=SCOPE):
    """Create a WebACL (registered for teardown). Returns the Summary dict."""
    name = name or ctx.unique_name("sim2real-behav-waf-acl-")
    created = _retry_transient(
        lambda: w.create_web_acl(
            Name=name, Scope=scope,
            DefaultAction=default_action or {"Allow": {}},
            Rules=rules or [],
            VisibilityConfig=_visibility_config(name.replace("-", "")),
            Tags=[{"Key": "Team", "Value": "sim2real"}],
        )
    )["Summary"]
    ctx.on_cleanup(lambda: _delete_locked(w, "web_acl", name, scope, created["Id"]))
    return created

def _managed_rule_group_rule(name, vendor, group, priority=0):
    return {
        "Name": name,
        "Priority": priority,
        "Statement": {"ManagedRuleGroupStatement": {"VendorName": vendor, "Name": group}},
        "OverrideAction": {"None": {}},
        "VisibilityConfig": _visibility_config(name.replace("-", "")),
    }

@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A WebACL referencing an AWS managed rule group gets a computed capacity matching
    the group's published Capacity, and the statement round-trips through GetWebACL."""
    w = ctx.client("wafv2")
    described = _retry_transient(
        lambda: w.describe_managed_rule_group(
            VendorName="AWS", Name="AWSManagedRulesCommonRuleSet", Scope=SCOPE
        )
    )
    expected_capacity = described["Capacity"]

    rule = _managed_rule_group_rule(
        "use-common-ruleset", "AWS", "AWSManagedRulesCommonRuleSet", priority=0
    )
    check_resp = _retry_transient(lambda: w.check_capacity(Scope=SCOPE, Rules=[rule]))
    assert check_resp["Capacity"] == expected_capacity, (
        check_resp["Capacity"], expected_capacity
    )

    summary = _create_web_acl(ctx, w, rules=[rule])
    got = w.get_web_acl(Name=summary["Name"], Scope=SCOPE, Id=summary["Id"])
    rules_back = got["WebACL"]["Rules"]
    assert len(rules_back) == 1, ("expected 1 rule on GetWebACL", len(rules_back))
    stmt = rules_back[0]["Statement"]["ManagedRuleGroupStatement"]
    assert stmt["Name"] == "AWSManagedRulesCommonRuleSet", (
        "AWSManagedRulesCommonRuleSet", stmt["Name"]
    )
    assert stmt["VendorName"] == "AWS", ("AWS", stmt["VendorName"])

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
