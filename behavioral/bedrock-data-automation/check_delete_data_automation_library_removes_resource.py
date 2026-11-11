"""delete-data-automation-library-removes-resource."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "delete-data-automation-library-removes-resource"
GROUP = "lifecycle-library"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDataAutomationLibrary transitions ACTIVE -> DELETING -> removed; Get eventually fails
    with ResourceNotFoundException."""
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-lib-")
    library_arn = bda.create_data_automation_library(libraryName=name)["libraryArn"]

    # Sanity: it exists before delete.
    existing = bda.get_data_automation_library(libraryArn=library_arn)["library"]
    assert existing["libraryArn"] == library_arn, f"expected {library_arn}, got {existing.get('libraryArn')}"

    bda.delete_data_automation_library(libraryArn=library_arn)

    code, message = _poll_until_rejected(
        lambda: bda.get_data_automation_library(libraryArn=library_arn),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r} ({message})"
    assert message == "The specified library Arn not found.", f"unexpected message: {message!r}"


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
