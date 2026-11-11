"""cancel-import-task-invalid-state-fails."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-import-task-invalid-state-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CancelImportTask on a nonexistent import id raises ResourceNotFoundException with its exact message,
    while DescribeImportTasks answers normally."""
    logs = ctx.client("logs")

    listed = logs.describe_import_tasks()
    assert "imports" in listed, f"expected 'imports' key in DescribeImportTasks response: {listed!r}"

    # Real import ids are UUID-shaped; a non-hex/dashed id like
    # "sim2real-nonexistent-import-..." fails format validation first and
    # yields InvalidParameterException instead of exercising the
    # not-found path. Use a well-formed-but-unknown UUID instead.
    bogus_import_id = str(uuid.uuid4())

    code, message = _error(lambda: logs.cancel_import_task(importId=bogus_import_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_message = "No matching import found."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )


def _error(fn):
    """Call fn() expecting a ClientError; return its (Code, Message). A success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
