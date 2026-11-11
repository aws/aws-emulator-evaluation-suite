"""list-notebook-executions-invalid-status-filter-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-notebook-executions-invalid-status-filter-rejected"
GROUP = "ordering"
SERVICES = ["emr"]


def _service_message(text, message, service="AWSEditors"):
    """`text` as the EMR backend `service` words a refusal; only its per-call request id is taken
    from the actual message."""
    request_id = (message or "").rsplit("Request ID: ", 1)[-1].split(";", 1)[0]
    return (
        f"{text} (Service: {service}; Status Code: 400; Error Code: InvalidRequestException; "
        f"Request ID: {request_id}; Proxy: null)"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListNotebookExecutions with a Status outside the documented enum fails with InvalidRequestException,
    HTTP 400 and AWS's exact message, while a valid Status returns a list."""
    emr = ctx.client("emr")

    code, status, message = _error(lambda: emr.list_notebook_executions(Status="NOT_A_REAL_STATUS"))
    assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code!r}"
    assert status == 400, f"expected HTTP 400, got {status!r}"
    expected = _service_message("Invalid Execution Status: NOT_A_REAL_STATUS", message)
    assert message == expected, f"expected the message {expected!r}, got {message!r}"

    # Positive control: an identical call shape with a valid Status enum value succeeds.
    resp = emr.list_notebook_executions(Status="FINISHED")
    assert isinstance(resp["NotebookExecutions"], list), (
        f"expected NotebookExecutions to be a list, got {resp['NotebookExecutions']!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, HTTP status, message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], err.response["ResponseMetadata"]["HTTPStatusCode"], error.get("Message")
    raise AssertionError(f"expected a ClientError rejecting the invalid Status filter, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
