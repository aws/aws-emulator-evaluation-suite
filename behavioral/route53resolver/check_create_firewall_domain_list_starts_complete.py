"""create-firewall-domain-list-starts-complete."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-firewall-domain-list-starts-complete"
GROUP = 'firewall-domain-list'
SERVICES = ['route53resolver']

TAGS_KV = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}]

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created (empty) FirewallDomainList is immediately COMPLETE with DomainCount 0."""
    r53 = ctx.client("route53resolver")
    name = ctx.unique_name("sim2real-behav-fdl-")
    resp = r53.create_firewall_domain_list(
        CreatorRequestId=ctx.unique_name("sim2real-behav-cr-"), Name=name, Tags=TAGS_KV
    )
    dl = resp["FirewallDomainList"]
    dl_id = dl["Id"]
    ctx.on_cleanup(lambda x=dl_id: r53.delete_firewall_domain_list(FirewallDomainListId=x))
    assert dl["Name"] == name, f"expected Name {name!r}, got {dl['Name']!r}"
    assert dl["Status"] == "COMPLETE", f"expected COMPLETE, got {dl['Status']}"
    assert dl.get("DomainCount", 0) == 0, f"expected DomainCount 0, got {dl.get('DomainCount')}"

    got = r53.get_firewall_domain_list(FirewallDomainListId=dl_id)["FirewallDomainList"]
    assert got["Status"] == "COMPLETE", f"expected COMPLETE on independent read, got {got['Status']}"
    assert got["DomainCount"] == 0, f"expected DomainCount 0 on independent read, got {got['DomainCount']}"

    # It must show up in the list.
    found = False
    paginator_token = None
    while True:
        kwargs = {"NextToken": paginator_token} if paginator_token else {}
        page = r53.list_firewall_domain_lists(**kwargs)
        if any(item["Id"] == dl_id for item in page.get("FirewallDomainLists", [])):
            found = True
            break
        paginator_token = page.get("NextToken")
        if not paginator_token:
            break
    assert found, "created domain list not visible via ListFirewallDomainLists"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
