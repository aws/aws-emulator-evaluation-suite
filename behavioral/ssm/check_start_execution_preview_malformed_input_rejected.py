"""start-execution-preview-malformed-input-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-execution-preview-malformed-input-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_SLEEP_DOC = {
    "schemaVersion": "0.3",
    "description": "sim2real execution preview malformed-input test document",
    "mainSteps": [
        {"name": "SleepStep", "action": "aws:sleep", "inputs": {"Duration": "PT1S"}},
    ],
}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartExecutionPreview with both Targets and TargetMaps (mutually exclusive) is rejected with
    ValidationException; with neither set it succeeds and GetExecutionPreview reaches Success."""
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-ssm-preview-param-")
    ssm.create_document(
        Name=doc_name,
        DocumentType="Automation",
        DocumentFormat="JSON",
        Content=json.dumps(_SLEEP_DOC),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))
    _wait_doc_active(ctx, doc_name)

    # Targets and TargetMaps are mutually exclusive, but both are supplied.
    code, message = _error(
        lambda: ssm.start_execution_preview(
            DocumentName=doc_name,
            ExecutionInputs={
                "Automation": {
                    "Targets": [{"Key": "InstanceIds", "Values": ["i-1234567890abcdef0"]}],
                    "TargetMaps": [{"InstanceIds": ["i-1234567890abcdef0"]}],
                    "TargetParameterName": "InstanceIds",
                }
            },
        )
    )
    assert code == "ValidationException", code
    assert message == "Targets and TargetMaps cannot both be provided.", message

    # Positive control: the same document with neither field set succeeds.
    resp = ssm.start_execution_preview(DocumentName=doc_name)
    preview_id = resp["ExecutionPreviewId"]
    assert preview_id, resp

    got = _poll_preview_terminal(ssm, preview_id)
    assert got["ExecutionPreviewId"] == preview_id, got
    assert got["Status"] == "Success", got


def _error(fn):
    """Call fn(); return its botocore error (code, message), raising if the call succeeds."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_preview_terminal(ssm, preview_id: str, timeout_s: float = 60.0) -> dict:
    deadline = time.monotonic() + timeout_s
    while True:
        got = ssm.get_execution_preview(ExecutionPreviewId=preview_id)
        if got["Status"] in ("Success", "Failed"):
            return got
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"preview {preview_id} never reached a terminal status within {timeout_s}s: {got}"
            )
        time.sleep(2.0)


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

