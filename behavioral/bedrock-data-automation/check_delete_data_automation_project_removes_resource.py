"""delete-data-automation-project-removes-resource."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-data-automation-project-removes-resource"
GROUP = "lifecycle-project"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDataAutomationProject permanently removes the Project; a subsequent Get and a
    subsequent Update on the same ARN both fail with ResourceNotFoundException."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-proj-")
    project_arn = bda.create_data_automation_project(
        projectName=name,
        standardOutputConfiguration={},
    )["projectArn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(bda, project_arn))

    # Sanity: it exists before delete.
    bda.get_data_automation_project(projectArn=project_arn)

    bda.delete_data_automation_project(projectArn=project_arn)

    get_code, get_message = _client_error(lambda: bda.get_data_automation_project(projectArn=project_arn))
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from Get on a deleted project, got {get_code!r}"
    )
    assert get_message == "Project Arn not found.", f"unexpected message: {get_message!r}"

    update_code, update_message = _client_error(
        lambda: bda.update_data_automation_project(
            projectArn=project_arn,
            standardOutputConfiguration={},
        )
    )
    assert update_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from Update on a deleted project, got {update_code!r}"
    )
    assert update_message == "Project Arn not found.", f"unexpected message: {update_message!r}"


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_ignore_missing(bda, project_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        bda.delete_data_automation_project(projectArn=project_arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
