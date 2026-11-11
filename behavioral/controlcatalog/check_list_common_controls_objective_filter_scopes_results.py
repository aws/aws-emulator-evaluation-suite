"""list-common-controls-objective-filter-scopes-results."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-common-controls-objective-filter-scopes-results"
GROUP = "filtering"
SERVICES = ["controlcatalog"]


def _paginate_common_controls(cc, **kwargs):
    token = None
    while True:
        params = dict(kwargs)
        if token:
            params["NextToken"] = token
        page = cc.list_common_controls(**params)
        yield from page.get("CommonControls", [])
        token = page.get("NextToken")
        if not token:
            break


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CommonControlFilter.Objectives narrows ListCommonControls to exactly the common controls
    the unfiltered catalog itself reports belonging to that objective -- no wrong-objective
    control admitted, and none dropped."""
    cc = ctx.client("controlcatalog")

    unfiltered = list(_paginate_common_controls(cc, MaxResults=100))
    assert unfiltered, "expected the Control Catalog to contain at least one common control"
    target_objective_arn = unfiltered[0]["Objective"]["Arn"]

    filtered = list(
        _paginate_common_controls(
            cc, MaxResults=100, CommonControlFilter={"Objectives": [{"Arn": target_objective_arn}]}
        )
    )
    assert filtered, "expected at least one common control for the chosen objective"

    for common_control in filtered:
        assert common_control["Objective"]["Arn"] == target_objective_arn, (
            f"filtered result {common_control['Arn']} carries Objective.Arn "
            f"{common_control['Objective']['Arn']!r}, expected {target_objective_arn!r}"
        )

    filtered_arns = {c["Arn"] for c in filtered}
    expected_arns = {
        c["Arn"] for c in unfiltered if c["Objective"]["Arn"] == target_objective_arn
    }
    assert filtered_arns == expected_arns, (
        f"CommonControlFilter.Objectives=[{target_objective_arn}] returned {sorted(filtered_arns)}, "
        f"but the unfiltered catalog shows {sorted(expected_arns)} belonging to that objective"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
