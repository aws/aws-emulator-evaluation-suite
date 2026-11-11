"""get-control-concurrent-reads-consistent."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "get-control-concurrent-reads-consistent"
GROUP = "concurrency"
SERVICES = ["controlcatalog"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent GetControl calls for the same control ARN all succeed and agree on every field
    (read-only reference data must be thread-safe and free of read races)."""
    cc = ctx.client("controlcatalog")
    real_arn = cc.list_controls(MaxResults=1)["Controls"][0]["Arn"]

    def _get():
        return cc.get_control(ControlArn=real_arn)

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(lambda _: _get(), range(10)))

    assert len(results) == 10, f"expected 10 concurrent GetControl results, got {len(results)}"
    first = results[0]
    fields = (
        "Arn",
        "Name",
        "Description",
        "Behavior",
        "Severity",
        "ParameterRequirementSummary",
        "GovernedResources",
        "GovernedProviders",
        "Aliases",
    )
    for result in results[1:]:
        for field in fields:
            assert result.get(field) == first.get(field), (
                f"concurrent GetControl calls disagreed on field {field}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
