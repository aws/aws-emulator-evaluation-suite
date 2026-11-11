"""op-notebook-execution-ops-reject-unknown-execution."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-notebook-execution-ops-reject-unknown-execution"
GROUP = 'overly-permissive'
SERVICES = ['emr']

THROTTLE_CODES = ("ThrottlingException", "TooManyRequestsException")

def _error(fn):
    """Invoke *fn*, asserting it is rejected; return the (code, message) pair."""
    try:
        fn()
    except Exception as exc:
        err = (getattr(exc, "response", {}) or {}).get("Error", {})
        return err.get("Code", type(exc).__name__), err.get("Message", "")
    raise AssertionError("expected the operation to be rejected, but it succeeded")

def _error_stable(fn, attempts: int = 6):
    """Like ``_error`` but retries through throttling so the assertion observes
    the operation's real rejection code rather than a rate-limit artefact."""
    code, message = _error(fn)
    for attempt in range(attempts - 1):
        if code not in THROTTLE_CODES:
            break
        time.sleep(5 * (attempt + 1))
        code, message = _error(fn)
    return code, message

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
    """DescribeNotebookExecution and StopNotebookExecution reject an unknown execution id with
    InvalidRequestException and AWS's exact message."""
    emr = ctx.client("emr")
    bogus = "ex-" + "Z" * 25
    cases = {
        "DescribeNotebookExecution": lambda: emr.describe_notebook_execution(
            NotebookExecutionId=bogus
        ),
        "StopNotebookExecution": lambda: emr.stop_notebook_execution(
            NotebookExecutionId=bogus
        ),
    }
    for op, call in cases.items():
        code, message = _error_stable(call)
        assert code == "InvalidRequestException", f"{op}: expected InvalidRequestException, got {code}"
        expected = _service_message("Execution does not exist", message)
        assert message == expected, f"{op}: expected the message {expected!r}, got {message!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
