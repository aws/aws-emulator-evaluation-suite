"""send-automation-signal-nonexistent-execution-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-automation-signal-nonexistent-execution-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm"]

_PAUSE_DOC = {
    "schemaVersion": "0.3",
    "description": "sim2real automation pause test document",
    "mainSteps": [
        {"name": "PauseStep", "action": "aws:pause", "inputs": {}},
    ],
}


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendAutomationSignal against an unknown execution id is rejected, has no
    side effect, and a real waiting execution still accepts the same signal."""
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-ssm-pause-")
    ssm.create_document(
        Name=doc_name,
        DocumentType="Automation",
        DocumentFormat="JSON",
        Content=json.dumps(_PAUSE_DOC),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))
    _wait_doc_active(ctx, doc_name)

    exec_id = ssm.start_automation_execution(DocumentName=doc_name)["AutomationExecutionId"]
    ctx.on_cleanup(lambda: _best_effort_stop(ctx, exec_id))
    _wait_automation_status(ctx, exec_id, {"Waiting"}, timeout_s=90)

    # Break exactly one thing: target a well-formed but nonexistent execution id.
    bogus_id = str(uuid.uuid4())
    code, message = _client_error(
        lambda: ssm.send_automation_signal(AutomationExecutionId=bogus_id, SignalType="Resume")
    )
    assert code == "AutomationExecutionNotFoundException", code
    assert message == "The input automation execution does not exist.", message

    # Effect absent: no execution with the bogus id was ever fabricated.
    found = ssm.describe_automation_executions(
        Filters=[{"Key": "ExecutionId", "Values": [bogus_id]}]
    )["AutomationExecutionMetadataList"]
    assert found == [], found

    # Positive control: the same signal against the REAL waiting execution succeeds.
    # Resume requires the paused step's name as Payload (AWS validates this even
    # though our earlier PauseStep-targeted call above was rejected for a
    # different, unrelated reason -- the bogus execution id).
    ssm.send_automation_signal(
        AutomationExecutionId=exec_id,
        SignalType="Resume",
        Payload={"StepName": ["PauseStep"]},
    )
    final = _wait_automation_status(
        ctx, exec_id, {"Success", "Failed", "TimedOut", "Cancelled"}, timeout_s=90
    )
    assert final == "Success", final


# ===== helpers =====
def _client_error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises,
    because a target accepting a signal real AWS refuses must fail as an acceptance, not a code
    mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _best_effort_stop(ctx, exec_id: str) -> None:
    ssm = ctx.client("ssm")
    try:
        ssm.stop_automation_execution(AutomationExecutionId=exec_id)
    except ClientError as err:
        # An execution that is gone or already finished has nothing left to stop.
        if err.response["Error"]["Code"] not in (
            "AutomationExecutionNotFoundException",
            "InvalidAutomationStatusUpdateException",
        ):
            raise


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


def _wait_automation_status(ctx, exec_id: str, terminal: set, timeout_s: float = 90.0) -> str:
    ssm = ctx.client("ssm")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = ssm.get_automation_execution(AutomationExecutionId=exec_id)["AutomationExecution"][
            "AutomationExecutionStatus"
        ]
        if last in terminal:
            return last
        time.sleep(1.5)
    raise AssertionError(f"execution {exec_id} never reached {terminal}, last status {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
