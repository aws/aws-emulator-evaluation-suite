"""execution-preview-start-then-get-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "execution-preview-start-then-get-lifecycle"
GROUP = "state-machine"
SERVICES = ["ssm"]

_PREVIEW_DOC = {
    "schemaVersion": "0.3",
    "description": "sim2real execution preview test document",
    "mainSteps": [
        {"name": "SleepStep", "action": "aws:sleep", "inputs": {"Duration": "PT1S"}},
    ],
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartExecutionPreview creates a preview job whose computed results
    (StepPreviews for the actual document steps) become retrievable via
    GetExecutionPreview once the job reaches a terminal state."""
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-ssm-preview-")
    ssm.create_document(
        Name=doc_name,
        DocumentType="Automation",
        DocumentFormat="JSON",
        Content=json.dumps(_PREVIEW_DOC),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))
    _wait_doc_active(ctx, doc_name)

    preview_id = ssm.start_execution_preview(DocumentName=doc_name)["ExecutionPreviewId"]

    final = _poll_until(
        lambda: ssm.get_execution_preview(ExecutionPreviewId=preview_id),
        lambda resp: resp["Status"] in ("Success", "Failed"),
        timeout_s=90,
        interval_s=2.0,
    )
    assert final["Status"] == "Success", final.get("StatusMessage")
    assert final["ExecutionPreviewId"] == preview_id, (preview_id, final["ExecutionPreviewId"])
    assert "EndedAt" in final, final
    # StepPreviews is a map of impact category (Mutating/NonMutating/Undetermined)
    # to the count of steps in that category -- not keyed by step name. Our
    # single-step document contributes exactly one step to exactly one category.
    step_previews = final["ExecutionPreview"]["Automation"]["StepPreviews"]
    assert isinstance(step_previews, dict) and step_previews, step_previews
    assert sum(step_previews.values()) == 1, step_previews
    assert step_previews.get("NonMutating") == 1, (
        "aws:sleep touches no resource and should score NonMutating",
        step_previews,
    )


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


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never satisfied within {timeout_s}s, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
