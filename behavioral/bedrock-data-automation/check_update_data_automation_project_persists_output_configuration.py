"""update-data-automation-project-persists-output-configuration."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "update-data-automation-project-persists-output-configuration"
GROUP = "lifecycle-project"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDataAutomationProject's new standardOutputConfiguration replaces the prior one and is
    durably reflected by a subsequent Get, not the configuration the project was created with."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-proj-")
    project_arn = bda.create_data_automation_project(
        projectName=name,
        standardOutputConfiguration={},
    )["projectArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_project(projectArn=project_arn))
    create_status = _wait_terminal(bda, project_arn)
    assert create_status == "COMPLETED", f"expected project to reach COMPLETED, got {create_status!r}"

    before = bda.get_data_automation_project(projectArn=project_arn)["project"]
    before_state = before.get("standardOutputConfiguration", {}).get("document", {}).get(
        "generativeField", {}
    ).get("state")
    assert before_state != "ENABLED", (
        f"expected the project created with an empty output configuration to not have "
        f"generativeField ENABLED, got {before_state!r}"
    )

    bda.update_data_automation_project(
        projectArn=project_arn,
        standardOutputConfiguration={"document": {"generativeField": {"state": "ENABLED"}}},
    )
    update_status = _wait_terminal(bda, project_arn)
    assert update_status == "COMPLETED", f"expected project to reach COMPLETED, got {update_status!r}"

    after = bda.get_data_automation_project(projectArn=project_arn)["project"]
    after_state = after["standardOutputConfiguration"]["document"]["generativeField"]["state"]
    assert after_state == "ENABLED", (
        f"expected UpdateDataAutomationProject's new generativeField state to persist as ENABLED, "
        f"got {after_state!r}"
    )


def _wait_terminal(bda, project_arn: str) -> str:
    return _poll_until(
        lambda: bda.get_data_automation_project(projectArn=project_arn)["project"]["status"],
        lambda s: s in ("COMPLETED", "FAILED"),
        timeout_s=60.0,
        interval_s=2.0,
    )


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
