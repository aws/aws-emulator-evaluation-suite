"""control-mapping-filter-by-control-arn-scopes-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "control-mapping-filter-by-control-arn-scopes-results"
GROUP = "data-integrity"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListControlMappings with Filter.ControlArns=[X] returns only mappings for control X."""
    cc = ctx.client("controlcatalog")
    unfiltered = cc.list_control_mappings(MaxResults=50)["ControlMappings"]
    distinct_arns = {m["ControlArn"] for m in unfiltered}
    assert len(distinct_arns) > 1, (
        f"need >1 distinct ControlArn on an unfiltered page to prove the filter narrows anything, "
        f"got {distinct_arns}"
    )
    control_arn = unfiltered[0]["ControlArn"]

    filtered = cc.list_control_mappings(Filter={"ControlArns": [control_arn]}, MaxResults=1000)
    items = filtered["ControlMappings"]

    assert len(items) >= 1, "filtering by the sample mapping's own ControlArn returned nothing"
    assert all(m["ControlArn"] == control_arn for m in items), "filter did not scope all mappings to the control ARN"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
