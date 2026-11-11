"""list-firewall-rules-priority-ordering."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-firewall-rules-priority-ordering"
GROUP = "ordering"
SERVICES = ["route53resolver"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFirewallRules returns the rules of a rule group ordered by ascending Priority,
    regardless of the order in which the rules were created."""
    r53r = ctx.client("route53resolver")

    group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crg-"),
        Name=ctx.unique_name("sim2real-fwgroup-")[:64],
        Tags=[{"Key": "env", "Value": "behavioral-test"}],
    )["FirewallRuleGroup"]["Id"]

    # Deliberately create rules with priorities out of ascending order.
    creation_order_priorities = [300, 100, 200]
    for priority in creation_order_priorities:
        list_id = r53r.create_firewall_domain_list(
            CreatorRequestId=ctx.unique_name("sim2real-r53r-cfdl-"),
            Name=ctx.unique_name("sim2real-fwdomains-")[:64],
            Tags=[{"Key": "env", "Value": "behavioral-test"}],
        )["FirewallDomainList"]["Id"]
        ctx.on_cleanup(lambda lid=list_id: _safe_delete_domain_list(r53r, lid))
        r53r.update_firewall_domains(FirewallDomainListId=list_id, Operation="ADD", Domains=[f"p{priority}.test."])

        r53r.create_firewall_rule(
            CreatorRequestId=ctx.unique_name("sim2real-r53r-cfr-"),
            FirewallRuleGroupId=group_id,
            FirewallDomainListId=list_id,
            Priority=priority,
            Action="ALLOW",
            Name=ctx.unique_name(f"sim2real-rule-{priority}-")[:64],
        )

    # Register the rule-group cleanup last so it runs FIRST (cleanups run LIFO): the
    # group delete cascades its rules, which must happen before the domain lists (whose
    # cleanups were registered earlier and therefore run after) can be deleted.
    ctx.on_cleanup(lambda: _safe_delete_group(r53r, group_id))

    rules = r53r.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]
    our_priorities = [r["Priority"] for r in rules if r["Priority"] in creation_order_priorities]

    assert our_priorities == sorted(creation_order_priorities), (
        f"expected ascending priority order {sorted(creation_order_priorities)}, "
        f"got {our_priorities}"
    )


def _safe_delete_group(r53r, group_id):
    try:
        r53r.delete_firewall_rule_group(FirewallRuleGroupId=group_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_domain_list(r53r, list_id):
    try:
        r53r.delete_firewall_domain_list(FirewallDomainListId=list_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
