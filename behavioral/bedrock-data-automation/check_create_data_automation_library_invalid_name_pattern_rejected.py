"""create-data-automation-library-invalid-name-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-data-automation-library-invalid-name-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["bedrock-data-automation"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A libraryName containing characters outside ^[a-zA-Z0-9-_]+$ (e.g. a space) is rejected
    with ValidationException and no Library is created; a valid name still succeeds (positive
    control)."""
    bda = ctx.client("bedrock-data-automation")
    invalid_name = ctx.unique_name("sim2real-bda-lib") + " not valid"

    code, message = _client_error(lambda: bda.create_data_automation_library(libraryName=invalid_name))
    assert code == "ValidationException", (
        f"a libraryName containing a space was expected to be rejected with "
        f"ValidationException, got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value at 'libraryName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z0-9-_]+"
    ), f"unexpected message: {message!r}"

    listed = bda.list_data_automation_libraries()["libraries"]
    assert not any(lib["libraryName"] == invalid_name for lib in listed), (
        f"the rejected libraryName {invalid_name!r} appeared in "
        f"ListDataAutomationLibraries: {listed!r}"
    )

    valid_name = ctx.unique_name("sim2real-bda-lib-valid")
    arn = bda.create_data_automation_library(libraryName=valid_name)["libraryArn"]
    ctx.on_cleanup(lambda: bda.delete_data_automation_library(libraryArn=arn))
    got_name = bda.get_data_automation_library(libraryArn=arn)["library"]["libraryName"]
    assert got_name == valid_name, (
        f"positive control: expected the created library's name to be {valid_name!r}, "
        f"got {got_name!r}"
    )


def _client_error(fn):
    """Call fn(); return its botocore (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
