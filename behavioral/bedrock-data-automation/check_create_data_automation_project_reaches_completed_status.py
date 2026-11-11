"""create-data-automation-project-reaches-completed-status."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-data-automation-project-reaches-completed-status"
GROUP = "lifecycle-project"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDataAutomationProject's status transitions to a terminal COMPLETED state, and
    projectStage defaults to LIVE when not specified (matching the CreateBlueprint contract)."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-proj-")
    created = bda.create_data_automation_project(
        projectName=name,
        standardOutputConfiguration={},
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )
    project_arn = created["projectArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_project(projectArn=project_arn))
    assert created["projectStage"] == "LIVE", f"expected projectStage LIVE, got {created['projectStage']!r}"

    status = _poll_until(
        lambda: bda.get_data_automation_project(projectArn=project_arn)["project"]["status"],
        lambda s: s in ("COMPLETED", "FAILED"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert status == "COMPLETED", f"expected terminal status COMPLETED, got {status!r}"

    project = bda.get_data_automation_project(projectArn=project_arn)["project"]
    assert project["projectName"] == name, f"expected projectName {name!r}, got {project['projectName']!r}"
    assert project["projectStage"] == "LIVE", f"expected projectStage LIVE, got {project['projectStage']!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() <= deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
