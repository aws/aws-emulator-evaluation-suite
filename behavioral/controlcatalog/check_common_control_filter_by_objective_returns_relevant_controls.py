"""common-control-filter-by-objective-returns-relevant-controls."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "common-control-filter-by-objective-returns-relevant-controls"
GROUP = "data-integrity"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCommonControls with a CommonControlFilter.Objectives=[X] scopes every returned common
    control to objective X, still includes the common control the filter ARN was sourced from, and
    omits no unfiltered common control that shares that objective."""
    cc = ctx.client("controlcatalog")
    unfiltered = cc.list_common_controls(MaxResults=100)["CommonControls"]
    assert len(unfiltered) >= 1, "expected the Control Catalog to report at least one common control"
    sample_cc = unfiltered[0]
    objective_arn = sample_cc["Objective"]["Arn"]

    filtered = cc.list_common_controls(
        CommonControlFilter={"Objectives": [{"Arn": objective_arn}]}, MaxResults=100
    )
    items = filtered["CommonControls"]

    assert len(items) >= 1, "filtering by an objective that the sample common control belongs to returned nothing"
    assert all(c["Objective"]["Arn"] == objective_arn for c in items), "filter did not scope all results to the objective"
    assert any(c["Arn"] == sample_cc["Arn"] for c in items), "the sourcing common control itself was not in the filtered set"

    same_objective_unfiltered = {c["Arn"] for c in unfiltered if c["Objective"]["Arn"] == objective_arn}
    filtered_arns = {c["Arn"] for c in items}
    missing = same_objective_unfiltered - filtered_arns
    assert not missing, f"filter dropped common controls that share the objective in the unfiltered listing: {missing}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
