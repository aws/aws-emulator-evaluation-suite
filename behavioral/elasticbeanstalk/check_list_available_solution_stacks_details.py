"""list-available-solution-stacks-details."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "list-available-solution-stacks-details"
GROUP = 'configuration-metadata'
SERVICES = ['elasticbeanstalk']

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAvailableSolutionStacks returns names plus per-stack permitted file types."""
    eb = ctx.client("elasticbeanstalk")
    resp = eb.list_available_solution_stacks()
    names = resp["SolutionStacks"]
    details = resp["SolutionStackDetails"]
    assert names, "solution stack list must not be empty"
    detail_names = [d["SolutionStackName"] for d in details]
    assert detail_names == names, (
        f"SolutionStackDetails must be a 1:1, same-order projection of SolutionStacks: "
        f"got {len(detail_names)} detail names vs {len(names)} names, "
        f"first mismatch at {next((i for i, (a, b) in enumerate(zip(detail_names, names)) if a != b), 'length')}"
    )
    assert any(d.get("PermittedFileTypes") for d in details), (
        "at least one stack must declare permitted file types"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
