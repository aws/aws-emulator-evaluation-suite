"""send-automation-signal-unknown-step-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-automation-signal-unknown-step-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendAutomationSignal Resume naming a step absent from the document is refused
    AutomationStepNotFoundException and leaves the execution Waiting; resuming the real step
    drives it to Success."""
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-ssm-automation-")
    content = json.dumps(
        {
            "schemaVersion": "0.3",
            "description": "pauses at a single named step until resumed",
            "mainSteps": [
                {"name": "step1", "action": "aws:pause", "timeoutSeconds": "600", "inputs": {}}
            ],
        }
    )
    ssm.create_document(
        Content=content,
        Name=doc_name,
        DocumentType="Automation",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))

    execution_id = ssm.start_automation_execution(DocumentName=doc_name)["AutomationExecutionId"]

    def _stop():
        try:
            ssm.stop_automation_execution(AutomationExecutionId=execution_id)
        except ClientError as err:
            # An execution that is gone or already finished has nothing left to stop.
            if err.response["Error"]["Code"] not in (
                "AutomationExecutionNotFoundException",
                "InvalidAutomationStatusUpdateException",
            ):
                raise

    ctx.on_cleanup(_stop)

    status = _poll_until(
        lambda: ssm.get_automation_execution(AutomationExecutionId=execution_id)[
            "AutomationExecution"
        ]["AutomationExecutionStatus"],
        lambda s: s in ("Waiting", "Success", "Failed", "TimedOut", "Cancelled"),
        timeout_s=60.0,
        description="aws:pause step reaching Waiting",
    )
    assert status == "Waiting", f"expected the aws:pause step to reach Waiting, got {status}"

    def _bad_step():
        ssm.send_automation_signal(
            AutomationExecutionId=execution_id,
            SignalType="Resume",
            Payload={"StepName": ["this-step-does-not-exist"]},
        )

    bad_step_code, bad_step_message = _error(_bad_step)
    assert bad_step_code == "AutomationStepNotFoundException", (
        f"expected AutomationStepNotFoundException, got {bad_step_code}"
    )
    assert bad_step_message == (
        "Failed to process signal Resume. Step this-step-does-not-exist is not defined in "
        f"document: {doc_name} (version 1)."
    ), bad_step_message

    after_bad_signal = ssm.get_automation_execution(AutomationExecutionId=execution_id)[
        "AutomationExecution"
    ]["AutomationExecutionStatus"]
    assert after_bad_signal == "Waiting", (
        f"expected status unchanged at Waiting after the rejected signal, got {after_bad_signal}"
    )

    ssm.send_automation_signal(
        AutomationExecutionId=execution_id,
        SignalType="Resume",
        Payload={"StepName": ["step1"]},
    )

    final_status = _poll_until(
        lambda: ssm.get_automation_execution(AutomationExecutionId=execution_id)[
            "AutomationExecution"
        ]["AutomationExecutionStatus"],
        lambda s: s in ("Success", "Failed", "TimedOut", "Cancelled"),
        timeout_s=60.0,
        description="execution reaching a terminal state after Resume",
    )
    assert final_status == "Success", f"expected Success after Resume, got {final_status}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    if not predicate(value):
        raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {value!r}")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
