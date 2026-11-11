"""create-data-automation-project-default-project-type-is-async."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-data-automation-project-default-project-type-is-async"
GROUP = "state"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataAutomationProject with no projectType set defaults the Project to ASYNC."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bda-proj-type")
    # Deliberately omit projectType.
    arn = bda.create_data_automation_project(
        projectName=name,
        standardOutputConfiguration={},
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["projectArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_project(projectArn=arn))

    fetched = bda.get_data_automation_project(projectArn=arn)["project"]
    assert fetched["projectType"] == "ASYNC", (
        f"expected projectType to default to ASYNC when omitted, got {fetched.get('projectType')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
