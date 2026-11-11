"""create-data-automation-project-invalid-name-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-data-automation-project-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A projectName containing characters outside ^[a-zA-Z0-9-_]+$ (e.g. a slash) is rejected
    with ValidationException and no Project is created; a valid name still succeeds (positive
    control)."""
    bda = ctx.client("bedrock-data-automation")
    invalid_name = ctx.unique_name("sim2real-bda-proj") + "/bad"

    code, message = _error_code(
        lambda: bda.create_data_automation_project(projectName=invalid_name, standardOutputConfiguration={})
    )
    assert code == "ValidationException", (
        f"expected ValidationException for projectName={invalid_name!r}, got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value at 'projectName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z0-9-_]+"
    ), f"unexpected message: {message!r}"

    listed = bda.list_data_automation_projects()["projects"]
    assert not any(p["projectName"] == invalid_name for p in listed), (
        f"rejected projectName={invalid_name!r} must not appear in ListDataAutomationProjects, "
        f"but found it among {[p['projectName'] for p in listed]!r}"
    )

    valid_name = ctx.unique_name("sim2real-bda-proj-valid")
    arn = bda.create_data_automation_project(
        projectName=valid_name,
        standardOutputConfiguration={},
        tags=[{"key": "purpose", "value": "sim2real"}],
    )["projectArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_project(projectArn=arn))
    fetched_name = bda.get_data_automation_project(projectArn=arn)["project"]["projectName"]
    assert fetched_name == valid_name, (
        f"expected GetDataAutomationProject to reflect projectName={valid_name!r}, got {fetched_name!r}"
    )


def _error_code(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
