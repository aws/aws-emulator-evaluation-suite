"""send-automation-signal-nonexistent-step-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-automation-signal-nonexistent-step-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_SLEEP_DOC = """schemaVersion: "0.3"
mainSteps:
  - name: sleepStep
    action: aws:sleep
    inputs:
      Duration: PT2M
"""

_TERMINAL_STATUSES = {
    "Success",
    "Failed",
    "Cancelled",
    "TimedOut",
    "CompletedWithSuccess",
    "CompletedWithFailure",
}


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its ClientError (code, message). A success raises: the call is
    expected to be refused."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the signal to be refused, but it succeeded: {result!r}")


def _stop_quiet(ssm, execution_id) -> None:
    try:
        ssm.stop_automation_execution(AutomationExecutionId=execution_id)
    except ClientError as err:
        # An execution that is gone or already finished has nothing left to stop.
        if err.response["Error"]["Code"] not in (
            "AutomationExecutionNotFoundException",
            "InvalidAutomationStatusUpdateException",
        ):
            raise


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendAutomationSignal StopStep with an unknown StepExecutionId is refused
    AutomationStepNotFoundException and leaves the real step InProgress; the execution still
    stops via StopAutomationExecution."""
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-automation-stepnf-")
    ssm.create_document(
        Name=doc_name,
        Content=_SLEEP_DOC,
        DocumentType="Automation",
        DocumentFormat="YAML",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name))

    # Step signals are accepted only in Interactive mode (Auto mode refuses them with
    # InvalidAutomationSignalException), so the step is started with a StartStep signal.
    execution_id = ssm.start_automation_execution(DocumentName=doc_name, Mode="Interactive")[
        "AutomationExecutionId"
    ]
    ctx.on_cleanup(lambda: _stop_quiet(ssm, execution_id))
    _wait_for_status(ssm, execution_id, "Waiting")
    ssm.send_automation_signal(
        AutomationExecutionId=execution_id,
        SignalType="StartStep",
        Payload={"StepName": ["sleepStep"]},
    )
    step_execution_id = _wait_for_step_in_progress(ssm, execution_id, "sleepStep")

    bogus_step_execution_id = str(uuid.uuid4())
    assert bogus_step_execution_id != step_execution_id
    refused = _error(
        lambda: ssm.send_automation_signal(
            AutomationExecutionId=execution_id,
            SignalType="StopStep",
            Payload={"StepExecutionId": [bogus_step_execution_id]},
        )
    )
    assert refused == (
        "AutomationStepNotFoundException",
        "The step you are trying to stop doesn't exist.",
    ), refused

    # Still the same real step in progress; no step was invented.
    execution = ssm.get_automation_execution(AutomationExecutionId=execution_id)[
        "AutomationExecution"
    ]
    assert execution["AutomationExecutionStatus"] == "InProgress"
    steps = {s["StepName"]: s["StepStatus"] for s in execution["StepExecutions"]}
    assert steps.get("sleepStep") == "InProgress", steps
    assert bogus_step_execution_id not in {s.get("StepExecutionId") for s in execution["StepExecutions"]}

    ssm.stop_automation_execution(AutomationExecutionId=execution_id)
    _wait_for_terminal(ssm, execution_id)


def _wait_for_step_in_progress(ssm, execution_id, step_name, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        execution = ssm.get_automation_execution(AutomationExecutionId=execution_id)[
            "AutomationExecution"
        ]
        for step in execution.get("StepExecutions", []):
            if step.get("StepName") == step_name and step.get("StepStatus") == "InProgress":
                return step["StepExecutionId"]
        time.sleep(interval_s)
    raise AssertionError(f"step {step_name!r} never reached InProgress within {timeout_s}s")


def _wait_for_status(ssm, execution_id, wanted, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ssm.get_automation_execution(AutomationExecutionId=execution_id)[
            "AutomationExecution"
        ]["AutomationExecutionStatus"]
        if status == wanted:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"automation execution never reached {wanted} within {timeout_s}s; last {status!r}"
    )


def _wait_for_terminal(ssm, execution_id, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ssm.get_automation_execution(AutomationExecutionId=execution_id)[
            "AutomationExecution"
        ]["AutomationExecutionStatus"]
        if status in _TERMINAL_STATUSES:
            return status
        time.sleep(interval_s)
    raise AssertionError(
        f"automation execution never reached a terminal state within {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
