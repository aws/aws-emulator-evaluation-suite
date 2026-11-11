"""common-control-catalog-workflow-domain-objective-consistency."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "common-control-catalog-workflow-domain-objective-consistency"
GROUP = "e2e"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A common control's Domain and Objective references each resolve, by ARN, to a ListDomains and a
    ListObjectives entry with the same Name: the catalog hierarchy is navigable from a common control."""
    cc = ctx.client("controlcatalog")
    common_controls = cc.list_common_controls(MaxResults=1).get("CommonControls", [])
    assert common_controls, "ListCommonControls returned no common controls"
    entry = common_controls[0]
    domain_ref = entry["Domain"]
    objective_ref = entry["Objective"]

    domains_by_arn = {}
    token = None
    for _ in range(20):
        kwargs = {"MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_domains(**kwargs)
        for d in page.get("Domains", []):
            domains_by_arn[d["Arn"]] = d
        token = page.get("NextToken")
        if not token:
            break
    assert domain_ref["Arn"] in domains_by_arn, f"domain {domain_ref['Arn']} not found via ListDomains"
    listed_domain_name = domains_by_arn[domain_ref["Arn"]]["Name"]
    assert listed_domain_name == domain_ref["Name"], (
        f"ListDomains reports Name={listed_domain_name!r} for {domain_ref['Arn']} but the common "
        f"control's embedded Domain reference carries Name={domain_ref['Name']!r}"
    )

    objectives_by_arn = {}
    token = None
    for _ in range(20):
        kwargs = {"MaxResults": 100, "ObjectiveFilter": {"Domains": [{"Arn": domain_ref["Arn"]}]}}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_objectives(**kwargs)
        for o in page.get("Objectives", []):
            objectives_by_arn[o["Arn"]] = o
        token = page.get("NextToken")
        if not token:
            break
    assert objective_ref["Arn"] in objectives_by_arn, f"objective {objective_ref['Arn']} not found via ListObjectives"
    listed_objective_name = objectives_by_arn[objective_ref["Arn"]]["Name"]
    assert listed_objective_name == objective_ref["Name"], (
        f"ListObjectives reports Name={listed_objective_name!r} for {objective_ref['Arn']} but the "
        f"common control's embedded Objective reference carries Name={objective_ref['Name']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

