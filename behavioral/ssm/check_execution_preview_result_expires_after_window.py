"""execution-preview-result-expires-after-window."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "execution-preview-result-expires-after-window"
GROUP = "visibility-timeout-ttl"
SERVICES = ["ssm"]

_DOC_CONTENT = {
    "schemaVersion": "0.3",
    "description": "sim2real-behavioral minimal automation runbook for execution preview",
    "parameters": {"AutomationAssumeRole": {"type": "String", "default": ""}},
    "mainSteps": [
        {
            "name": "sleepStep",
            "action": "aws:sleep",
            "inputs": {"Duration": "PT1S"},
        }
    ],
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetExecutionPreview returns a started preview with a terminal Success or Failed Status.

    An unknown preview id fails ResourceNotFoundException with the "does not exist or is expired"
    message; expiry of a real preview is not waited for."""
    ssm = ctx.client("ssm")

    doc_name = ctx.unique_name("sim2real-ssm-preview-doc-")
    ssm.create_document(
        Name=doc_name,
        DocumentType="Automation",
        DocumentFormat="JSON",
        Content=json.dumps(_DOC_CONTENT),
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))

    start = ssm.start_execution_preview(DocumentName=doc_name)
    preview_id = start["ExecutionPreviewId"]
    assert preview_id, f"expected a non-empty ExecutionPreviewId, got {preview_id!r}"

    def _probe() -> dict[str, Any]:
        return ssm.get_execution_preview(ExecutionPreviewId=preview_id)

    result = _poll_until(
        _probe,
        lambda r: r["Status"] in ("Success", "Failed"),
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert result["ExecutionPreviewId"] == preview_id, (
        f"expected ExecutionPreviewId {preview_id}, got {result['ExecutionPreviewId']}"
    )
    assert result["Status"] in ("Success", "Failed"), (
        f"expected a terminal Status, got {result['Status']}"
    )

    # A syntactically valid but never-issued ExecutionPreviewId (matching the fixed UUID
    # pattern the API requires) is rejected the same way an expired one would be.
    bogus_id = str(uuid.uuid4())
    error = _error(lambda: ssm.get_execution_preview(ExecutionPreviewId=bogus_id))
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error!r}"
    )
    assert error["Message"] == (
        f"Execution preview '{bogus_id}' does not exist or is expired"
    ), error["Message"]


def _error(fn: Callable[[], Any]) -> dict:
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}")


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 120.0,
    interval_s: float = 5.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
