"""list-rule-groups-pagination-reflects-created."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-rule-groups-pagination-reflects-created"
GROUP = "resource-config"
SERVICES = ["network-firewall"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRuleGroups paginated with a small MaxResults and followed via NextToken surfaces
    every created rule group exactly once, with no duplicates or omissions across pages."""
    nfw = ctx.client("network-firewall")
    prefix = ctx.unique_name("sim2real-nfw-pg-")
    created_names = set()

    for i in range(3):
        name = f"{prefix}{i}"
        nfw.create_rule_group(
            RuleGroupName=name, Type="STATEFUL", Capacity=10,
            RuleGroup={"RulesSource": {"StatefulRules": [{
                "Action": "ALERT",
                "Header": {"Protocol": "TCP", "Source": "ANY", "SourcePort": "ANY",
                           "Direction": "ANY", "Destination": "ANY", "DestinationPort": "ANY"},
                "RuleOptions": [{"Keyword": "sid:1"}],
            }]}},
        )
        created_names.add(name)
        ctx.on_cleanup(lambda n=name: nfw.delete_rule_group(RuleGroupName=n))

    seen = []
    next_token = None
    pages = 0
    while True:
        kwargs = {"MaxResults": 2}
        if next_token:
            kwargs["NextToken"] = next_token
        page = nfw.list_rule_groups(**kwargs)
        pages += 1
        assert len(page.get("RuleGroups", [])) <= 2, (
            f"page {pages} returned {len(page.get('RuleGroups', []))} rule groups, "
            f"exceeding the requested MaxResults=2"
        )
        seen.extend(rg["Name"] for rg in page.get("RuleGroups", []) if rg["Name"] in created_names)
        next_token = page.get("NextToken")
        if not next_token or pages > 50:
            break

    assert pages >= 2, (
        f"MaxResults=2 with {len(created_names)} rule groups created by this check must span at "
        f"least 2 pages, but list_rule_groups returned everything in {pages} page(s) — pagination "
        f"was never exercised"
    )
    assert sorted(seen) == sorted(created_names), (
        f"pagination lost or duplicated rule groups: expected {sorted(created_names)}, saw {sorted(seen)}"
    )
    assert len(seen) == len(set(seen)), f"pagination returned a duplicate: {seen}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
