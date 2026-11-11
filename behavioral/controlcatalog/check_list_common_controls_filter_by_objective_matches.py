"""list-common-controls-filter-by-objective-matches."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-common-controls-filter-by-objective-matches"
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
    """ListCommonControls filtered by an objective ARN returns exactly the common controls that
    the unfiltered catalog itself shows belonging to that objective -- no wrong-objective control
    let in, and no matching control dropped."""
    cc = ctx.client("controlcatalog")

    token = None
    for _ in range(10):
        kwargs = {"MaxResults": 20}
        if token:
            kwargs["NextToken"] = token
        page = cc.list_objectives(**kwargs)
        for obj in page.get("Objectives", []):
            filtered = list(
                _paginate_common_controls(
                    cc, CommonControlFilter={"Objectives": [{"Arn": obj["Arn"]}]}, MaxResults=100
                )
            )
            if filtered:
                for c in filtered:
                    assert c["Objective"]["Arn"] == obj["Arn"], (
                        f"filtered result {c['Arn']} carries Objective.Arn "
                        f"{c['Objective']['Arn']!r}, expected {obj['Arn']!r}"
                    )

                filtered_arns = {c["Arn"] for c in filtered}
                expected_arns = {
                    c["Arn"]
                    for c in _paginate_common_controls(cc, MaxResults=100)
                    if c["Objective"]["Arn"] == obj["Arn"]
                }
                assert filtered_arns == expected_arns, (
                    f"CommonControlFilter.Objectives=[{obj['Arn']}] returned {sorted(filtered_arns)}, "
                    f"but the unfiltered catalog shows {sorted(expected_arns)} belonging to that objective"
                )
                return
        token = page.get("NextToken")
        if not token:
            break

    raise AssertionError("no objective with at least one mapped common control was found")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
