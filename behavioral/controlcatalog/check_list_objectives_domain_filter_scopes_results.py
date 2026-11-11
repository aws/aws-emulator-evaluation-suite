"""list-objectives-domain-filter-scopes-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-objectives-domain-filter-scopes-results"
GROUP = "filtering"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ObjectiveFilter.Domains narrows ListObjectives to only objectives belonging to that domain."""
    cc = ctx.client("controlcatalog")

    unfiltered = cc.list_objectives(MaxResults=100).get("Objectives", [])
    assert unfiltered, "expected the Control Catalog to contain at least one objective"
    target_domain_arn = unfiltered[0]["Domain"]["Arn"]

    filtered = cc.list_objectives(
        MaxResults=100, ObjectiveFilter={"Domains": [{"Arn": target_domain_arn}]}
    ).get("Objectives", [])
    assert filtered, "expected at least one objective for the chosen domain"

    for objective in filtered:
        assert objective["Domain"]["Arn"] == target_domain_arn, (
            f"expected every filtered objective to belong to domain {target_domain_arn}, "
            f"got {objective['Domain']['Arn']} on {objective['Arn']}"
        )

    filtered_arns = {o["Arn"] for o in filtered}
    same_domain_unfiltered = {
        o["Arn"] for o in unfiltered if o["Domain"]["Arn"] == target_domain_arn
    }
    assert same_domain_unfiltered.issubset(filtered_arns), (
        f"expected the filter to retain every unfiltered objective in domain "
        f"{target_domain_arn} ({sorted(same_domain_unfiltered)}), but it dropped "
        f"{sorted(same_domain_unfiltered - filtered_arns)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
