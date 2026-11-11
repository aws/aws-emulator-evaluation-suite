"""list-data-automation-projects-reflects-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "list-data-automation-projects-reflects-lifecycle"
GROUP = "state"
SERVICES = ["bedrock-data-automation"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDataAutomationProjects includes a newly created Project and stops including it once deleted."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-proj-")
    project_arn = bda.create_data_automation_project(
        projectName=name,
        standardOutputConfiguration={},
    )["projectArn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(bda, project_arn))

    found = _poll_until(
        lambda: project_arn in _list_all_project_arns(bda),
        lambda present: present,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert found, f"ListDataAutomationProjects never included newly created {project_arn}"

    bda.delete_data_automation_project(projectArn=project_arn)

    gone = _poll_until(
        lambda: project_arn in _list_all_project_arns(bda),
        lambda present: not present,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert not gone, f"ListDataAutomationProjects still included deleted {project_arn}"


def _list_all_project_arns(bda) -> set[str]:
    arns: set[str] = set()
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = bda.list_data_automation_projects(**kwargs)
        arns.update(p["projectArn"] for p in resp.get("projects", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return arns


def _delete_ignore_missing(bda, project_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        bda.delete_data_automation_project(projectArn=project_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
