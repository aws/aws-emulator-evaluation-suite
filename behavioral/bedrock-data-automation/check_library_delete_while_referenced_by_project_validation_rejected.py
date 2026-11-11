"""library-delete-while-referenced-by-project-validation-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "library-delete-while-referenced-by-project-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]

# An empty configuration is explicitly documented as valid: default settings apply and can be
# inspected afterward via GetDataAutomationProject.
_STANDARD_OUTPUT: dict = {}
_TAGS = [{"key": "sim2real", "value": CHECK}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDataAutomationLibrary on a library a project references is refused with
    ValidationException and the exact message and the library stays ACTIVE; an unreferenced library
    deletes, and after the project is deleted the same library deletes too.
    """
    bda = ctx.client("bedrock-data-automation")

    # Positive control: DeleteDataAutomationLibrary succeeds on an unreferenced Library. Without
    # this, "rejects a referenced Library" is indistinguishable from "rejects every Library".
    control_name = ctx.unique_name("sim2real-bda-lib-control")
    control_arn = bda.create_data_automation_library(libraryName=control_name, tags=_TAGS)[
        "libraryArn"
    ]
    control_cleaned = {"done": False}

    def _cleanup_control():
        if not control_cleaned["done"]:
            bda.delete_data_automation_library(libraryArn=control_arn)

    ctx.on_cleanup(_cleanup_control)
    bda.delete_data_automation_library(libraryArn=control_arn)
    control_cleaned["done"] = True

    lib_name = ctx.unique_name("sim2real-bda-lib-inuse")
    library_arn = bda.create_data_automation_library(libraryName=lib_name, tags=_TAGS)["libraryArn"]

    proj_name = ctx.unique_name("sim2real-bda-proj-inuse")
    project_arn = bda.create_data_automation_project(
        projectName=proj_name,
        standardOutputConfiguration=_STANDARD_OUTPUT,
        dataAutomationLibraryConfiguration={"libraries": [{"libraryArn": library_arn}]},
        tags=_TAGS,
    )["projectArn"]

    cleaned_up = {"library": False, "project": False}

    def _cleanup_library():
        if not cleaned_up["library"]:
            bda.delete_data_automation_library(libraryArn=library_arn)

    def _cleanup_project():
        if not cleaned_up["project"]:
            bda.delete_data_automation_project(projectArn=project_arn)

    ctx.on_cleanup(_cleanup_library)
    ctx.on_cleanup(_cleanup_project)

    # Break exactly one thing relative to the positive control: a project references this library.
    code, message = _client_error(lambda: bda.delete_data_automation_library(libraryArn=library_arn))
    assert code == "ValidationException", f"unexpected code: {code} ({message})"
    assert message == (
        "Unable to delete the library as it is being referenced by some project. You must remove it "
        "from all referring projects before you can delete the library."
    ), f"unexpected message: {message!r}"

    # Effect absent: the Library is still there and ACTIVE.
    still_there = bda.get_data_automation_library(libraryArn=library_arn)["library"]
    assert still_there["status"] == "ACTIVE"

    # Restore: remove the blocking reference, then the identical delete call succeeds.
    bda.delete_data_automation_project(projectArn=project_arn)
    cleaned_up["project"] = True
    bda.delete_data_automation_library(libraryArn=library_arn)
    cleaned_up["library"] = True

    final_code, final_message = _poll_until_rejected(
        lambda: bda.get_data_automation_library(libraryArn=library_arn),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert final_code == "ResourceNotFoundException", f"unexpected code: {final_code} ({final_message})"
    assert final_message == "The specified library Arn not found.", f"unexpected message: {final_message!r}"


def _client_error(fn):
    """The (code, message) of the ClientError fn raises; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until_rejected(fn, timeout_s=60.0, interval_s=2.0):
    """Call fn() until it raises a ClientError and return that error's (Code, Message). A call
    that keeps succeeding past the deadline raises, so it never reads as a code."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() <= deadline:
        try:
            last = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"call still succeeded after {timeout_s}s (last result: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
