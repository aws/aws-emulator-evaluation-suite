"""create-firewall-rule-group-and-rule-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-firewall-rule-group-and-rule-lifecycle"
GROUP = 'firewall-rule-group'
SERVICES = ['route53resolver']

def _poll(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _delete_rule_if_present(r53, group_id, dl_id):
    """Teardown for the rule ``run`` deletes itself; a rule already gone is not a failure."""
    try:
        r53.delete_firewall_rule(FirewallRuleGroupId=group_id, FirewallDomainListId=dl_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A FirewallRule shows up in ListFirewallRules, bumps the group's RuleCount, and
    disappears (RuleCount back to 0) after DeleteFirewallRule."""
    r53 = ctx.client("route53resolver")
    group_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-frg-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=group_id: r53.delete_firewall_rule_group(FirewallRuleGroupId=x))
    group = r53.get_firewall_rule_group(FirewallRuleGroupId=group_id)[
        "FirewallRuleGroup"
    ]
    assert group["Status"] == "COMPLETE", f"new rule group should be COMPLETE, got {group['Status']}"
    assert group.get("RuleCount", 0) == 0, f"new rule group should have 0 rules: {group}"

    dl_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-fdl-"),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_id: r53.delete_firewall_domain_list(FirewallDomainListId=x))
    rule_name = ctx.unique_name("sim2real-behav-fr-")
    rule = r53.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        FirewallRuleGroupId=group_id,
        FirewallDomainListId=dl_id,
        Priority=100,
        Action="ALLOW",
        Name=rule_name,
    )["FirewallRule"]
    ctx.on_cleanup(lambda g=group_id, d=dl_id: _delete_rule_if_present(r53, g, d))
    assert rule["Priority"] == 100, f"expected Priority 100, got {rule['Priority']}"
    assert rule["Action"] == "ALLOW", f"expected Action ALLOW, got {rule['Action']}"
    assert rule["FirewallRuleGroupId"] == group_id, (
        f"expected FirewallRuleGroupId {group_id}, got {rule['FirewallRuleGroupId']}"
    )

    def listed_rule():
        rules = r53.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]
        for r in rules:
            if r["Name"] == rule_name:
                return r
        return None

    found = _poll(
        listed_rule,
        lambda r: r is not None,
        timeout_s=60,
        interval_s=2,
        description="rule visible via ListFirewallRules",
    )
    assert found["FirewallDomainListId"] == dl_id, (
        f"expected FirewallDomainListId {dl_id}, got {found['FirewallDomainListId']}"
    )
    assert found["Priority"] == 100, f"expected listed Priority 100, got {found['Priority']}"

    def rule_count():
        return r53.get_firewall_rule_group(FirewallRuleGroupId=group_id)[
            "FirewallRuleGroup"
        ].get("RuleCount", 0)

    _poll(
        rule_count,
        lambda c: c == 1,
        timeout_s=60,
        interval_s=2,
        description="rule group RuleCount reaches 1",
    )

    r53.delete_firewall_rule(FirewallRuleGroupId=group_id, FirewallDomainListId=dl_id)
    _poll(
        listed_rule,
        lambda r: r is None,
        timeout_s=60,
        interval_s=2,
        description="rule removed from ListFirewallRules",
    )
    _poll(
        rule_count,
        lambda c: c == 0,
        timeout_s=60,
        interval_s=2,
        description="rule group RuleCount back to 0",
    )

    try:
        r53.delete_firewall_rule(FirewallRuleGroupId=group_id, FirewallDomainListId=dl_id)
        raise AssertionError("deleting an already-deleted firewall rule should fail")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        message = _without_trace_id(e.response["Error"].get("Message"))
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException deleting a gone rule, got {code}"
        )
        expected = (
            "[RSLVR-02004] Can\u2019t locate the rule for the Firewall rule group ID: "
            f'"{group_id}" and Firewall domain list ID "{dl_id}".'
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
