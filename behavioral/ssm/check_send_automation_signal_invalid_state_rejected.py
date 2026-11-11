"""send-automation-signal-invalid-state-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-automation-signal-invalid-state-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Resume and Approve signals sent while an automation is InProgress are refused with
    InvalidAutomationSignalException and leave its status unchanged; the same Resume succeeds
    once the execution is Waiting at its aws:pause step.
    """
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-automation-signal-doc-")

    content = {
        "schemaVersion": "0.3",
        "description": "sim2real SendAutomationSignal fidelity check",
        "mainSteps": [
            {"name": "sleepStep", "action": "aws:sleep", "inputs": {"Duration": "PT15S"}},
            {"name": "pauseStep", "action": "aws:pause", "inputs": {}},
        ],
    }
    ssm.create_document(
        Content=json.dumps(content),
        Name=doc_name,
        DocumentType="Automation",
        DocumentFormat="JSON",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_document_quiet(ssm, doc_name))

    _poll_until(
        lambda: ssm.describe_document(Name=doc_name)["Document"]["Status"],
        lambda status: status == "Active",
        timeout_s=60.0,
        interval_s=2.0,
    )

    start_resp = ssm.start_automation_execution(DocumentName=doc_name)
    execution_id = start_resp["AutomationExecutionId"]
    ctx.on_cleanup(lambda: _stop_automation_quiet(ssm, execution_id))

    in_progress = _poll_until(
        lambda: ssm.get_automation_execution(AutomationExecutionId=execution_id)[
            "AutomationExecution"
        ]["AutomationExecutionStatus"],
        lambda status: status in ("InProgress", "Waiting", "Success", "Failed"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert in_progress == "InProgress", f"expected InProgress during sleep step, got {in_progress}"

    # Break exactly one thing: the same Resume/pauseStep call that succeeds below,
    # sent while the execution is still InProgress (not yet Waiting on pauseStep).
    early_resume = _error(
        lambda: ssm.send_automation_signal(
            AutomationExecutionId=execution_id,
            SignalType="Resume",
            Payload={"StepName": ["pauseStep"]},
        )
    )
    assert early_resume == (
        "InvalidAutomationSignalException",
        f"Failed to process signal Resume, automation {execution_id} is in InProgress "
        "status. Resume signal can only be sent to automations in Waiting status.",
    ), early_resume

    unaffected_by_resume = ssm.get_automation_execution(AutomationExecutionId=execution_id)[
        "AutomationExecution"
    ]["AutomationExecutionStatus"]
    assert unaffected_by_resume == "InProgress", (
        f"rejected Resume signal changed execution status to {unaffected_by_resume}"
    )

    approve = _error(
        lambda: ssm.send_automation_signal(
            AutomationExecutionId=execution_id, SignalType="Approve"
        )
    )
    assert approve == (
        "InvalidAutomationSignalException",
        f"Failed to process signal Approve, automation {execution_id} is in InProgress "
        "status. Approve signal can only be sent to automations in Waiting status.",
    ), approve

    unaffected = ssm.get_automation_execution(AutomationExecutionId=execution_id)[
        "AutomationExecution"
    ]["AutomationExecutionStatus"]
    assert unaffected == "InProgress", f"rejected signal changed execution status to {unaffected}"

    waiting = _poll_until(
        lambda: ssm.get_automation_execution(AutomationExecutionId=execution_id)[
            "AutomationExecution"
        ]["AutomationExecutionStatus"],
        lambda status: status in ("Waiting", "Success", "Failed"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert waiting == "Waiting", f"expected Waiting at the pause step, got {waiting}"

    # Positive control: a signal valid for the current (Waiting) state succeeds.
    # Resume (like StartStep) requires the target step name as its payload.
    ssm.send_automation_signal(
        AutomationExecutionId=execution_id,
        SignalType="Resume",
        Payload={"StepName": ["pauseStep"]},
    )

    final = _poll_until(
        lambda: ssm.get_automation_execution(AutomationExecutionId=execution_id)[
            "AutomationExecution"
        ]["AutomationExecutionStatus"],
        lambda status: status in ("Success", "Failed", "TimedOut", "Cancelled"),
        timeout_s=60.0,
        interval_s=2.0,
    )
    assert final == "Success", f"expected Success after Resume, got {final}"


def _error(fn) -> tuple[str, str]:
    """Return the ClientError (code, message) fn raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the signal to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _delete_document_quiet(ssm, name: str) -> None:
    try:
        ssm.delete_document(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidDocument":
            raise


def _stop_automation_quiet(ssm, execution_id: str) -> None:
    try:
        ssm.stop_automation_execution(AutomationExecutionId=execution_id)
    except ClientError as err:
        # An execution that is gone or already finished has nothing left to stop.
        if err.response["Error"]["Code"] not in (
            "AutomationExecutionNotFoundException",
            "InvalidAutomationStatusUpdateException",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
