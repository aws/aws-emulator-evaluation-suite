"""batch-create-firewall-rule-partial-failure."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-create-firewall-rule-partial-failure"
GROUP = 'firewall-rule-batch'
SERVICES = ['route53resolver']

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchCreateFirewallRule reports per-entry success/failure, not an all-or-nothing outcome."""
    r53 = ctx.client("route53resolver")
    group_id = r53.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-frg-"),
        Tags=TAGS_KV,
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda x=group_id: r53.delete_firewall_rule_group(FirewallRuleGroupId=x))
    dl_id = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"),
        Name=ctx.unique_name("sim2real-behav-fdl-"),
        Tags=TAGS_KV,
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda x=dl_id: r53.delete_firewall_domain_list(FirewallDomainListId=x))
    good_name = ctx.unique_name("sim2real-behav-fr-good-")
    bogus_dl = ctx.unique_name("sim2real-behav-rslvr-fdl-doesnotexist-")
    bad_name = ctx.unique_name("sim2real-behav-fr-bad-")

    resp = r53.batch_create_firewall_rule(
        CreateFirewallRuleEntries=[
            {
                "CreatorRequestId": ctx.unique_name("sim2real-behav-cr-"),
                "FirewallDomainListId": dl_id,
                "FirewallRuleGroupId": group_id,
                "Priority": 500,
                "Action": "ALLOW",
                "Name": good_name,
            },
            {
                "CreatorRequestId": ctx.unique_name("sim2real-behav-cr-"),
                "FirewallDomainListId": bogus_dl,
                "FirewallRuleGroupId": group_id,
                "Priority": 501,
                "Action": "ALLOW",
                "Name": bad_name,
            },
        ]
    )
    created_names = {r["Name"] for r in resp.get("CreatedFirewallRules", [])}
    create_errors = resp.get("CreateErrors", [])
    error_names = {
        e.get("FirewallRule", {}).get("Name")
        for e in create_errors
        if isinstance(e.get("FirewallRule"), dict)
    }

    assert good_name in created_names, f"expected {good_name} to succeed: {resp}"
    assert bad_name not in created_names, f"expected {bad_name} to NOT be created: {resp}"
    assert len(create_errors) == 1, (
        f"expected exactly one per-entry error, got {len(create_errors)}: {resp}"
    )
    assert bad_name in error_names, f"expected the error entry to name {bad_name}: {resp}"
    assert create_errors[0].get("Code") == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the nonexistent domain list, got: {create_errors[0]}"
    )
    assert create_errors[0].get("Message") == (
        f'[RSLVR-02025] Can\u2019t find the resource with ID "{bogus_dl}".'
    ), create_errors[0]
    ctx.on_cleanup(lambda g=group_id, d=dl_id: r53.delete_firewall_rule(FirewallRuleGroupId=g, FirewallDomainListId=d))

    listed = r53.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]
    listed_names = {r["Name"] for r in listed}
    assert good_name in listed_names, f"expected {good_name} visible via ListFirewallRules: {listed}"
    assert bad_name not in listed_names, f"expected {bad_name} absent from ListFirewallRules: {listed}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
