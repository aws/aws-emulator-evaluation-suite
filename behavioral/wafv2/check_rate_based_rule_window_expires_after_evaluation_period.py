"""rate-based-rule-window-expires-after-evaluation-period."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rate-based-rule-window-expires-after-evaluation-period"
GROUP = "visibility-timeout-ttl"
SERVICES = ["wafv2"]


#: WAFUnsupportedAggregateKeyTypeException's message for a rule not keyed on IP.
UNSUPPORTED_AGGREGATE_MESSAGE = (
    "The rule that you've named doesn't aggregate solely on the IP address or solely on "
    "the forwarded IP address. This call is only available for rate-based rules with an "
    "AggregateKeyType setting of IP or FORWARDED_IP."
)


def _error(fn):
    """Return (code, message) of the ClientError fn raises. A call that succeeds raises
    AssertionError: the caller expects a refusal."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetRateBasedStatementManagedKeys returns empty IPv4/IPv6 key lists for an unvisited IP-keyed
    rate-based rule, and refuses a CONSTANT-keyed rule with WAFUnsupportedAggregateKeyTypeException.

    Reference: https://docs.aws.amazon.com/waf/latest/APIReference/API_GetRateBasedStatementManagedKeys.html
    """
    wafv2 = ctx.client("wafv2")
    name = ctx.unique_name("sim2real-ratebased-")
    scope = "REGIONAL"
    acl_vis = {"SampledRequestsEnabled": False, "CloudWatchMetricsEnabled": False, "MetricName": name}

    ip_rule_name = "rate-ip"
    constant_rule_name = "rate-constant"
    rules = [
        {
            "Name": ip_rule_name,
            "Priority": 1,
            "Statement": {
                "RateBasedStatement": {
                    "Limit": 100,
                    "AggregateKeyType": "IP",
                    "EvaluationWindowSec": 300,
                }
            },
            "Action": {"Count": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": ip_rule_name,
            },
        },
        {
            "Name": constant_rule_name,
            "Priority": 2,
            "Statement": {
                "RateBasedStatement": {
                    "Limit": 100,
                    "AggregateKeyType": "CONSTANT",
                    "EvaluationWindowSec": 300,
                    "ScopeDownStatement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                }
            },
            "Action": {"Count": {}},
            "VisibilityConfig": {
                "SampledRequestsEnabled": False,
                "CloudWatchMetricsEnabled": False,
                "MetricName": constant_rule_name,
            },
        },
    ]

    created = wafv2.create_web_acl(
        Name=name, Scope=scope, DefaultAction={"Allow": {}}, Rules=rules, VisibilityConfig=acl_vis,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-ratebased"}],
    )
    summary = created["Summary"]
    acl_id = summary["Id"]

    def _cleanup():
        try:
            cur = wafv2.get_web_acl(Name=name, Scope=scope, Id=acl_id)
            wafv2.delete_web_acl(Name=name, Scope=scope, Id=acl_id, LockToken=cur["LockToken"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "WAFNonexistentItemException":
                raise

    ctx.on_cleanup(_cleanup)

    # Empty because no traffic has reached the rule.
    ip_keys = wafv2.get_rate_based_statement_managed_keys(
        Scope=scope, WebACLName=name, WebACLId=acl_id, RuleName=ip_rule_name
    )
    ipv4 = ip_keys.get("ManagedKeysIPV4") or {}
    ipv6 = ip_keys.get("ManagedKeysIPV6") or {}
    assert isinstance(ipv4.get("Addresses"), list), f"unexpected ManagedKeysIPV4 shape: {ip_keys}"
    assert isinstance(ipv6.get("Addresses"), list), f"unexpected ManagedKeysIPV6 shape: {ip_keys}"
    assert ipv4["Addresses"] == [], f"expected no managed IPv4 keys on an unvisited rule, got {ipv4}"
    assert ipv6["Addresses"] == [], f"expected no managed IPv6 keys on an unvisited rule, got {ipv6}"

    # CONSTANT aggregation does no per-IP key tracking.
    holder = {}

    def _attempt_unsupported():
        holder["resp"] = wafv2.get_rate_based_statement_managed_keys(
            Scope=scope, WebACLName=name, WebACLId=acl_id, RuleName=constant_rule_name
        )

    code, message = _error(_attempt_unsupported)
    assert code == "WAFUnsupportedAggregateKeyTypeException", (
        f"expected WAFUnsupportedAggregateKeyTypeException, got {code}"
    )
    assert message == UNSUPPORTED_AGGREGATE_MESSAGE, message
    assert "resp" not in holder, "call should have raised, not returned a response"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
