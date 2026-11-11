"""batch-delete-firewall-rule-removes-targeted-rules."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-delete-firewall-rule-removes-targeted-rules"
GROUP = 'firewall-rule-batch'
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


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchDeleteFirewallRule removes exactly the rules it names: they disappear from
    ListFirewallRules while an unnamed rule in the same group stays listed."""
    r53 = ctx.client("route53resolver")
    group_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-frg-")
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=group_id: r53.delete_firewall_rule_group(FirewallRuleGroupId=x))

    dl_target_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-fdl-")
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_target_id: r53.delete_firewall_domain_list(FirewallDomainListId=x))
    dl_spared_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=ctx.unique_name("sim2real-behav-fdl-")
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_spared_id: r53.delete_firewall_domain_list(FirewallDomainListId=x))

    rule_target_name = ctx.unique_name("sim2real-behav-fr-target-")
    r53.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        FirewallRuleGroupId=group_id,
        FirewallDomainListId=dl_target_id,
        Priority=600,
        Action="ALLOW",
        Name=rule_target_name,
    )
    rule_spared_name = ctx.unique_name("sim2real-behav-fr-spared-")
    r53.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        FirewallRuleGroupId=group_id,
        FirewallDomainListId=dl_spared_id,
        Priority=601,
        Action="ALLOW",
        Name=rule_spared_name,
    )
    ctx.on_cleanup(
        lambda g=group_id, d=dl_spared_id: r53.delete_firewall_rule(FirewallRuleGroupId=g, FirewallDomainListId=d)
    )

    before = {r["Name"] for r in r53.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]}
    assert {rule_target_name, rule_spared_name} <= before, f"both rules must exist before the batch delete: {before}"

    resp = r53.batch_delete_firewall_rule(
        DeleteFirewallRuleEntries=[
            {"FirewallRuleGroupId": group_id, "FirewallDomainListId": dl_target_id}
        ]
    )
    assert not resp.get("DeleteErrors"), f"unexpected delete errors: {resp}"
    deleted = resp.get("DeletedFirewallRules", [])
    assert len(deleted) == 1, f"expected exactly one deleted rule for one targeted entry, got {deleted!r}: {resp}"
    assert deleted[0].get("FirewallDomainListId") == dl_target_id, (
        f"batch delete reported deleting domain list {deleted[0].get('FirewallDomainListId')!r}, "
        f"expected the targeted {dl_target_id!r}: {resp}"
    )

    def rules_by_name():
        rules = r53.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]
        return {r["Name"] for r in rules}

    final_names = _poll(
        rules_by_name, lambda names: rule_target_name not in names,
        timeout_s=30, interval_s=1, description="targeted rule removed from ListFirewallRules",
    )
    assert rule_target_name not in final_names, f"targeted rule still present: {final_names}"
    assert rule_spared_name in final_names, f"untargeted rule was also removed by the batch delete: {final_names}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
