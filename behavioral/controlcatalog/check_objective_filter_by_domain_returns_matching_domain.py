"""objective-filter-by-domain-returns-matching-domain."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "objective-filter-by-domain-returns-matching-domain"
GROUP = "data-integrity"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListObjectives with an ObjectiveFilter.Domains=[X] scopes every returned objective to
    domain X, still includes the objective the filter ARN was sourced from, and drops none of
    the domain's other objectives that an unfiltered listing already showed."""
    cc = ctx.client("controlcatalog")
    unfiltered = cc.list_objectives(MaxResults=100)["Objectives"]
    assert unfiltered, "expected the Control Catalog to contain at least one objective"
    sample_obj = unfiltered[0]
    domain_arn = sample_obj["Domain"]["Arn"]

    filtered = cc.list_objectives(ObjectiveFilter={"Domains": [{"Arn": domain_arn}]}, MaxResults=100)
    objs = filtered["Objectives"]

    assert len(objs) >= 1, "filtering by a domain that the sample objective belongs to returned nothing"
    assert all(o["Domain"]["Arn"] == domain_arn for o in objs), "filter did not scope all results to the domain"
    assert any(o["Arn"] == sample_obj["Arn"] for o in objs), "the sourcing objective itself was not in the filtered set"

    same_domain_unfiltered = {o["Arn"] for o in unfiltered if o["Domain"]["Arn"] == domain_arn}
    filtered_arns = {o["Arn"] for o in objs}
    assert same_domain_unfiltered.issubset(filtered_arns), (
        f"filter dropped objectives belonging to the domain: {same_domain_unfiltered - filtered_arns}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
