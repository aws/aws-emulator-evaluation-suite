"""batch-update-firewall-rule-limit-exceeded-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-update-firewall-rule-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["route53resolver"]

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real"}]

# BatchUpdateFirewallRule documents LimitExceededException ("The request caused one or
# more limits to be exceeded") as a whole-call error, distinct from the per-entry
# UpdateErrors it normally uses for bad references. The exact per-request entry-count
# cap is not published (Route 53's public quota page only documents "Rules in a DNS
# Firewall rule group: 100"), so this uses an entry count an order of magnitude beyond
# that documented quota to reliably trip whichever cap the service enforces.
_ENTRY_COUNT = 1001


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An oversized BatchUpdateFirewallRule batch is rejected wholesale with
    LimitExceededException and leaves the rule untouched, not even its one legitimate entry
    applied; a correctly-sized batch update on the same rule still succeeds."""
    r53r = ctx.client("route53resolver")
    domain_list_id = _create_domain_list_with_domain(ctx, r53r, "sim2real-batch-test-domain.example")
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
    # A rule holds both its group and its domain list, so it must be deleted first
    # (on_cleanup runs LIFO) or DeleteFirewallRuleGroup/DeleteFirewallDomainList both
    # fail with ConflictException and leak.
    ctx.on_cleanup(lambda: _delete_rule(r53r, group_id, domain_list_id))
    before = _find_rule(r53r, group_id, domain_list_id)
    assert before is not None, "rule vanished immediately after CreateFirewallRule"

    valid_entry = {
        "FirewallRuleGroupId": group_id,
        "FirewallDomainListId": domain_list_id,
        "Priority": 100,
        "Action": "BLOCK",
        "BlockResponse": "NXDOMAIN",
    }
    oversized_batch = [dict(valid_entry) for _ in range(_ENTRY_COUNT)]

    code, message = _error_code(
        lambda: r53r.batch_update_firewall_rule(UpdateFirewallRuleEntries=oversized_batch)
    )
    assert code == "LimitExceededException", f"expected LimitExceededException, got {code!r}"
    expected = (
        "[RSLVR-02052] The number of firewall rules in the update batch exceeds the allowed "
        'maximum. Provide fewer than "10" rules.'
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = _find_rule(r53r, group_id, domain_list_id)
    assert after is not None, "rule disappeared after the rejected oversized batch"
    assert after["ModificationTime"] == before["ModificationTime"], (
        "oversized batch mutated the rule despite being rejected wholesale"
    )

    r53r.batch_update_firewall_rule(
        UpdateFirewallRuleEntries=[
            {
                "FirewallRuleGroupId": group_id,
                "FirewallDomainListId": domain_list_id,
                "Priority": 250,
                "Action": "BLOCK",
                "BlockResponse": "NXDOMAIN",
            }
        ]
    )
    control = _find_rule(r53r, group_id, domain_list_id)
    assert control is not None, "rule vanished after a correctly-sized batch update"
    assert control["Priority"] == 250, f"expected Priority 250 after batch update, got {control['Priority']!r}"


def _error_code(fn):
    """Call fn(); return botocore Error.Code of the ClientError it raises. A call that
    succeeds fails the check: a target accepting what AWS refuses must not read as an
    error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), _without_trace_id(error.get("Message"))
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _create_domain_list_with_domain(ctx, r53r, domain: str) -> str:
    list_id = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-cr-"),
        Name=ctx.unique_name("sim2real-fdl-"),
        Tags=TAGS_KV,
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda: _delete_domain_list(r53r, list_id))
    r53r.update_firewall_domains(FirewallDomainListId=list_id, Operation="ADD", Domains=[domain])
    deadline = time.monotonic() + 60.0
    status = None
    while time.monotonic() < deadline:
        status = r53r.get_firewall_domain_list(FirewallDomainListId=list_id)["FirewallDomainList"]["Status"]
        if status == "COMPLETE":
            break
        time.sleep(2.0)
    assert status == "COMPLETE", f"domain list never reached COMPLETE, last status {status!r}"
    return list_id


def _delete_rule(r53r, group_id: str, domain_list_id: str) -> None:
    try:
        r53r.delete_firewall_rule(FirewallRuleGroupId=group_id, FirewallDomainListId=domain_list_id)
    except r53r.exceptions.ResourceNotFoundException:
        pass


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


def _find_rule(r53r, group_id: str, domain_list_id: str):
    for rule in r53r.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]:
        if rule.get("FirewallDomainListId") == domain_list_id:
            return rule
    return None


_TRACE_ID = ' Trace Id: "'


def _without_trace_id(message):
    """The message minus Route 53 Resolver's per-request ' Trace Id: "..."' suffix."""
    message = message or ""
    head, sep, _ = message.rpartition(_TRACE_ID)
    return head if sep and message.endswith('"') else message


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
