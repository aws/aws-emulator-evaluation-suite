"""send-automation-signal-unknown-execution-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-automation-signal-unknown-execution-rejected"
GROUP = "error-semantics"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SendAutomationSignal on a fabricated AutomationExecutionId is refused
    AutomationExecutionNotFoundException and creates no execution; Resume on a real waiting
    execution is accepted and runs it to Success."""
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-ssm-automation-")
    content = json.dumps(
        {
            "schemaVersion": "0.3",
            "description": "pauses immediately so the execution stays addressable",
            "mainSteps": [
                {"name": "step1", "action": "aws:pause", "timeoutSeconds": "600", "inputs": {}}
            ],
        }
    )
    ssm.create_document(Content=content, Name=doc_name, DocumentType="Automation")
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
        timeout_s=90.0,
    )
    assert status == "Waiting", f"expected the aws:pause step to reach Waiting, got {status}"

    fake_execution_id = str(uuid.uuid4())

    def _call():
        ssm.send_automation_signal(AutomationExecutionId=fake_execution_id, SignalType="Approve")

    code, message = _error(_call)
    assert code == "AutomationExecutionNotFoundException", (
        f"expected AutomationExecutionNotFoundException, got {code}"
    )
    assert message == "The input automation execution does not exist.", message

    found = ssm.describe_automation_executions(
        Filters=[{"Key": "ExecutionId", "Values": [fake_execution_id]}]
    )["AutomationExecutionMetadataList"]
    assert found == [], f"expected no execution for the fabricated id, found {found}"

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
        timeout_s=90.0,
    )
    assert final_status == "Success", f"expected Success after Resume, got {final_status}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError("expected send_automation_signal to raise, it succeeded")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value) and time.monotonic() < deadline:
        time.sleep(interval_s)
        value = probe()
    if not predicate(value):
        raise AssertionError(f"timed out waiting for predicate, last value {value!r}")
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
