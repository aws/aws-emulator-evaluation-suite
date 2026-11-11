"""update-firewall-rule-invalid-action-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-firewall-rule-invalid-action-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53resolver"]

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateFirewallRule that pairs Action=ALLOW with a BlockResponse (only valid for
    Action=BLOCK) is rejected with ValidationException, leaves the rule's Action and
    BlockResponse untouched, and a compatible update on the same rule still succeeds."""
    r53r = ctx.client("route53resolver")
    domain_list_id = _create_domain_list_with_domain(ctx, r53r, "sim2real-fw-test-domain.example")
    group_id = _create_rule_group(ctx, r53r)

    r53r.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        FirewallRuleGroupId=group_id,
        FirewallDomainListId=domain_list_id,
        Priority=100,
        Action="BLOCK",
        BlockResponse="NXDOMAIN",
        Name=ctx.unique_name("sim2real-fwrule-"),
    )
    ctx.on_cleanup(lambda: _delete_rule(r53r, group_id, domain_list_id))

    refusal = _error(
        lambda: r53r.update_firewall_rule(
            FirewallRuleGroupId=group_id,
            FirewallDomainListId=domain_list_id,
            Action="ALLOW",
            BlockResponse="NXDOMAIN",
        )
    )
    expected = (
        "ValidationException",
        "[RSLVR-02010] You can't provide a block option if the ACTION is ALLOW or ALERT.",
    )
    assert refusal == expected, f"expected {expected!r}, got {refusal!r}"

    rule = _find_rule(r53r, group_id, domain_list_id)
    assert rule is not None, "rule disappeared after the rejected update"
    assert rule["Action"] == "BLOCK", f"Action was mutated despite rejection: {rule['Action']}"
    assert rule["BlockResponse"] == "NXDOMAIN", f"BlockResponse was mutated despite rejection: {rule['BlockResponse']!r}"

    r53r.update_firewall_rule(
        FirewallRuleGroupId=group_id,
        FirewallDomainListId=domain_list_id,
        Priority=200,
    )
    rule2 = _find_rule(r53r, group_id, domain_list_id)
    assert rule2 is not None, "rule disappeared after a compatible update"
    assert rule2["Priority"] == 200, f"expected Priority 200 after update, got {rule2['Priority']!r}"


_TRACE_ID = ' Trace Id: "'


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, with the
    per-request X-Ray trace id suffix removed. A call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        message = err.get("Message", "")
        head, sep, _ = message.rpartition(_TRACE_ID)
        return err.get("Code"), (head if sep and message.endswith('"') else message)
    raise AssertionError(f"expected a ClientError, the call succeeded and returned {result!r}")


def _create_domain_list_with_domain(ctx, r53r, domain: str) -> str:
    list_id = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-fdl-"),
        Tags=TAGS_KV,
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda: _delete_domain_list(r53r, list_id))
    r53r.update_firewall_domains(FirewallDomainListId=list_id, Operation="ADD", Domains=[domain])
    _poll_domain_list_status(r53r, list_id, {"COMPLETE"}, timeout_s=60.0)
    return list_id


def _delete_domain_list(r53r, list_id: str) -> None:
    try:
        r53r.delete_firewall_domain_list(FirewallDomainListId=list_id)
    except r53r.exceptions.ResourceNotFoundException:
        pass


def _create_rule_group(ctx, r53r) -> str:
    group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-frg-"),
        Tags=TAGS_KV,
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_rule_group(r53r, group_id))
    return group_id


def _delete_rule_group(r53r, group_id: str) -> None:
    try:
        r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id)
    except r53r.exceptions.ResourceNotFoundException:
        pass


def _delete_rule(r53r, group_id: str, domain_list_id: str) -> None:
    try:
        r53r.delete_firewall_rule(FirewallRuleGroupId=group_id, FirewallDomainListId=domain_list_id)
    except r53r.exceptions.ResourceNotFoundException:
        pass


def _find_rule(r53r, group_id: str, domain_list_id: str):
    for rule in r53r.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]:
        if rule.get("FirewallDomainListId") == domain_list_id:
            return rule
    return None


def _poll_domain_list_status(r53r, list_id: str, terminal_statuses, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = r53r.get_firewall_domain_list(FirewallDomainListId=list_id)["FirewallDomainList"]["Status"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"domain list {list_id} did not reach {terminal_statuses} within {timeout_s}s; last status {status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
