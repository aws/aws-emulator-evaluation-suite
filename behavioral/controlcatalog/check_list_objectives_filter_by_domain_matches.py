"""list-objectives-filter-by-domain-matches."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-objectives-filter-by-domain-matches"
GROUP = "filtering"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListObjectives filtered by a domain ARN returns only objectives belonging to that domain,
    and every objective that the unfiltered list shows in that domain survives the filter."""
    cc = ctx.client("controlcatalog")
    domain = cc.list_domains(MaxResults=1)["Domains"][0]

    unfiltered = cc.list_objectives(MaxResults=100).get("Objectives", [])
    assert unfiltered, "expected the Control Catalog to contain at least one objective"
    same_domain_unfiltered = {o["Arn"] for o in unfiltered if o["Domain"]["Arn"] == domain["Arn"]}

    resp = cc.list_objectives(ObjectiveFilter={"Domains": [{"Arn": domain["Arn"]}]}, MaxResults=100)
    objectives = resp.get("Objectives", [])
    assert len(objectives) > 0, f"domain {domain['Arn']} has no objectives"
    for o in objectives:
        assert o["Domain"]["Arn"] == domain["Arn"], (
            f"filtered result included objective {o['Arn']} from domain {o['Domain']['Arn']}, "
            f"expected only {domain['Arn']}"
        )

    filtered_arns = {o["Arn"] for o in objectives}
    missing = same_domain_unfiltered - filtered_arns
    assert not missing, (
        f"objectives {missing} belong to domain {domain['Arn']} in the unfiltered list "
        f"but were absent from the filtered result"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
