"""firewall-rule-override-ttl-numeric-precision-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firewall-rule-override-ttl-numeric-precision-round-trip"
GROUP = "visibility-timeout-ttl"
SERVICES = ["route53resolver"]

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BlockOverrideTtl set on a BLOCK/OVERRIDE firewall rule is returned by
    ListFirewallRules with exact integer precision -- no rounding to the nearest minute,
    no truncation, and no drift from the value that was set."""
    r53r = ctx.client("route53resolver")

    list_id = r53r.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-cfdl-"),
        Name=ctx.unique_name("sim2real-fwdomains-")[:64],
        Tags=TAGS_KV,
    )["FirewallDomainList"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_domain_list(r53r, list_id))
    r53r.update_firewall_domains(FirewallDomainListId=list_id, Operation="ADD", Domains=["ttl-override.test."])

    group_id = r53r.create_firewall_rule_group(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-crg-"),
        Name=ctx.unique_name("sim2real-fwgroup-")[:64],
        Tags=TAGS_KV,
    )["FirewallRuleGroup"]["Id"]
    ctx.on_cleanup(lambda: _safe_delete_group(r53r, group_id))

    exact_ttl = 54321  # deliberately not a multiple of 60/3600 to catch rounding
    rule_name = ctx.unique_name("sim2real-rule-ttl-")[:64]
    r53r.create_firewall_rule(
        CreatorRequestId=ctx.unique_name("sim2real-r53r-cfr-"),
        FirewallRuleGroupId=group_id,
        FirewallDomainListId=list_id,
        Priority=100,
        Action="BLOCK",
        BlockResponse="OVERRIDE",
        BlockOverrideDomain="overridden.test.",
        BlockOverrideDnsType="CNAME",
        BlockOverrideTtl=exact_ttl,
        Name=rule_name,
    )
    ctx.on_cleanup(
        lambda g=group_id, d=list_id: r53r.delete_firewall_rule(FirewallRuleGroupId=g, FirewallDomainListId=d)
    )

    rules = r53r.list_firewall_rules(FirewallRuleGroupId=group_id)["FirewallRules"]
    matches = [r for r in rules if r["Name"] == rule_name]
    assert len(matches) == 1, f"expected exactly one matching rule, found {len(matches)}"

    ttl = matches[0]["BlockOverrideTtl"]
    assert ttl == exact_ttl and isinstance(ttl, int), (
        f"expected BlockOverrideTtl to round-trip exactly as {exact_ttl!r} (int), got {ttl!r}"
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
