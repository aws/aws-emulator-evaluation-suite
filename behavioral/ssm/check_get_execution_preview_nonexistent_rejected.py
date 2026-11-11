"""get-execution-preview-nonexistent-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-execution-preview-nonexistent-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

_PREVIEW_DOC = {
    "schemaVersion": "0.3",
    "description": "sim2real execution preview test document",
    "mainSteps": [
        {"name": "SleepStep", "action": "aws:sleep", "inputs": {"Duration": "PT1S"}},
    ],
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetExecutionPreview for an unknown preview id fails with ResourceNotFoundException and the
    exact "does not exist or is expired" message, while the id StartExecutionPreview returns is
    retrievable and echoed back."""
    ssm = ctx.client("ssm")

    bogus_id = str(uuid.uuid4())
    error = _error(lambda: ssm.get_execution_preview(ExecutionPreviewId=bogus_id))
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error!r}"
    )
    assert error["Message"] == (
        f"Execution preview '{bogus_id}' does not exist or is expired"
    ), error["Message"]

    # Positive control: a real preview id from a real StartExecutionPreview call
    # is retrievable without error.
    doc_name = ctx.unique_name("sim2real-ssm-preview-")
    ssm.create_document(
        Name=doc_name,
        DocumentType="Automation",
        DocumentFormat="JSON",
        Content=json.dumps(_PREVIEW_DOC),
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))
    _wait_doc_active(ctx, doc_name)

    preview_id = ssm.start_execution_preview(DocumentName=doc_name)["ExecutionPreviewId"]
    resp = ssm.get_execution_preview(ExecutionPreviewId=preview_id)
    assert resp["ExecutionPreviewId"] == preview_id, (
        f"expected {preview_id}, got {resp['ExecutionPreviewId']}"
    )
    assert resp["Status"] in ("Pending", "InProgress", "Success", "Failed"), resp["Status"]


def _error(fn):
    """Call fn(); return its botocore error dict. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected ResourceNotFoundException, but the call SUCCEEDED and returned {result!r}")


def _wait_doc_active(ctx, name: str, timeout_s: float = 60.0) -> None:
    ssm = ctx.client("ssm")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ssm.describe_document(Name=name)["Document"]["Status"]
        if status == "Active":
            return
        if status == "Failed":
            raise AssertionError(f"document {name} failed to become Active")
        time.sleep(1.0)
    raise AssertionError(f"document {name} never became Active within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
