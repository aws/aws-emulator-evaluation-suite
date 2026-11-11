"""get-data-automation-project-wrong-stage-filter-not-found-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-data-automation-project-wrong-stage-filter-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Project created only in DEVELOPMENT is not retrievable via GetDataAutomationProject
    with projectStage=LIVE -- ResourceNotFoundException, not a silent fallback to whatever
    stage exists."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bda-proj-stagefilter")
    arn = bda.create_data_automation_project(
        projectName=name, projectStage="DEVELOPMENT", standardOutputConfiguration={}
    )["projectArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_project(projectArn=arn))

    code, message = _client_error(lambda: bda.get_data_automation_project(projectArn=arn, projectStage="LIVE"))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} ({message})"
    assert message == "Project Arn not found.", f"unexpected message: {message!r}"

    # Positive control: the same ARN with the correct stage filter (or none) resolves fine.
    dev = bda.get_data_automation_project(projectArn=arn, projectStage="DEVELOPMENT")["project"]
    assert dev["projectArn"] == arn, f"expected projectArn {arn!r}, got {dev['projectArn']!r}"
    assert dev["projectStage"] == "DEVELOPMENT", (
        f"expected projectStage DEVELOPMENT, got {dev['projectStage']!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a stage-mismatched lookup real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
