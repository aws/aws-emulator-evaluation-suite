"""create-data-automation-project-duplicate-name-same-stage-conflict-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "create-data-automation-project-duplicate-name-same-stage-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Creating a second Project with the same projectName AND the same projectStage is
    rejected with ConflictException; the original Project's status/stage is untouched, and a
    differently-named create in the same stage still succeeds (positive control)."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bda-proj-dup")

    original_arn = bda.create_data_automation_project(
        projectName=name,
        projectStage="DEVELOPMENT",
        standardOutputConfiguration={},
        tags=[{"key": "env", "value": "sim2real"}],
    )["projectArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_project(projectArn=original_arn))

    # The Project must be durably readable before we probe the duplicate-create boundary.
    # GetDataAutomationProject defaults to the LIVE stage, so a DEVELOPMENT-stage project must be
    # queried with projectStage="DEVELOPMENT" explicitly.
    _poll_until(
        lambda: _project_readable(bda, original_arn),
        lambda readable: readable,
        timeout_s=30.0,
        interval_s=2.0,
    )

    code, message = _client_error(
        lambda: bda.create_data_automation_project(
            projectName=name, projectStage="DEVELOPMENT", standardOutputConfiguration={}
        )
    )
    assert code == "ConflictException", f"unexpected code: {code} ({message})"
    assert message == "Project name already exists.", f"unexpected message: {message!r}"

    # Effect absent: only the original Project exists under this name+stage.
    unchanged = bda.get_data_automation_project(projectArn=original_arn, projectStage="DEVELOPMENT")["project"]
    assert unchanged["projectArn"] == original_arn, f"expected {original_arn}, got {unchanged['projectArn']}"
    assert unchanged["projectStage"] == "DEVELOPMENT", f"expected DEVELOPMENT, got {unchanged['projectStage']}"

    # Positive control: a create with a distinct name in the same stage succeeds normally.
    other_name = ctx.unique_name("sim2real-bda-proj-dup-other")
    other_arn = bda.create_data_automation_project(
        projectName=other_name,
        projectStage="DEVELOPMENT",
        standardOutputConfiguration={},
        tags=[{"key": "env", "value": "sim2real"}],
    )["projectArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_project(projectArn=other_arn))
    other_project_name = bda.get_data_automation_project(projectArn=other_arn, projectStage="DEVELOPMENT")["project"][
        "projectName"
    ]
    assert other_project_name == other_name, f"expected {other_name}, got {other_project_name}"


def _client_error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _project_readable(bda, project_arn) -> bool:
    from botocore.exceptions import ClientError

    try:
        bda.get_data_automation_project(projectArn=project_arn, projectStage="DEVELOPMENT")
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return False
    return True


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
