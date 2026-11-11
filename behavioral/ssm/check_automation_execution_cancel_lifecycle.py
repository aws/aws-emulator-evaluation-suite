"""automation-execution-cancel-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "automation-execution-cancel-lifecycle"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StopAutomationExecution moves an InProgress automation to Cancelled, durably.
    Get and Describe must agree on the terminal state: end time set, step no longer running."""

    ssm = ctx.client("ssm")

    # A single aws:sleep step parks the execution in InProgress without managed instances.
    def _automation_doc_content(duration="PT10M"):
        return json.dumps(
            {
                "schemaVersion": "0.3",
                "description": "behavioral-fidelity-probe automation",
                "mainSteps": [
                    {
                        "name": "sleepStep",
                        "action": "aws:sleep",
                        "inputs": {"Duration": duration},
                    }
                ],
            }
        )

    def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0):
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if predicate(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"condition not met within {timeout_s}s. Last: {last!r}")

    def _call_with_retry(fn, retries=10, delay=3.0):
        from botocore.exceptions import ClientError

        last = None
        for _ in range(retries):
            try:
                return fn()
            except ClientError as exc:
                last = exc
                code = exc.response.get("Error", {}).get("Code")
                if code in ("TooManyUpdates", "ThrottlingException"):
                    time.sleep(delay)
                    continue
                raise
        raise last

    def _create_automation_document(duration="PT10M"):
        name = ctx.unique_name("sim2real-behav-probe-auto-")
        ctx.on_cleanup(lambda: ssm.delete_document(Name=name, Force=True))
        ssm.create_document(
            Content=_automation_doc_content(duration),
            Name=name,
            DocumentType="Automation",
            DocumentFormat="JSON",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        return name

    doc_name = _create_automation_document("PT10M")

    start_resp = _call_with_retry(
        lambda: ssm.start_automation_execution(DocumentName=doc_name)
    )
    execution_id = start_resp["AutomationExecutionId"]

    status = _poll_until(
        lambda: ssm.get_automation_execution(
            AutomationExecutionId=execution_id
        )["AutomationExecution"]["AutomationExecutionStatus"],
        lambda s: s in ("InProgress", "Waiting", "Success", "Failed", "Cancelled"),
        timeout_s=120,
        interval_s=3,
    )
    assert status == "InProgress", (
        f"an aws:sleep PT10M automation must sit in InProgress, got {status}"
    )

    listed = ssm.describe_automation_executions(
        Filters=[{"Key": "ExecutionId", "Values": [execution_id]}]
    )["AutomationExecutionMetadataList"]
    assert len(listed) == 1, listed
    assert listed[0]["DocumentName"] == doc_name, listed[0]
    assert listed[0]["AutomationExecutionStatus"] == "InProgress", listed[0]

    steps = ssm.describe_automation_step_executions(
        AutomationExecutionId=execution_id
    )["StepExecutions"]
    assert any(s["StepName"] == "sleepStep" for s in steps), steps

    ssm.stop_automation_execution(AutomationExecutionId=execution_id, Type="Cancel")

    final = _poll_until(
        lambda: ssm.get_automation_execution(
            AutomationExecutionId=execution_id
        )["AutomationExecution"]["AutomationExecutionStatus"],
        lambda s: s in ("Cancelled", "Success", "Failed", "TimedOut"),
        timeout_s=180,
        interval_s=3,
    )
    assert final == "Cancelled", final

    # A cancelled execution is terminal: it gets an end time, the step is no
    # longer running, and the list view agrees with the detail view.
    execution = ssm.get_automation_execution(
        AutomationExecutionId=execution_id
    )["AutomationExecution"]
    assert "ExecutionEndTime" in execution, execution
    assert execution["ExecutionEndTime"] >= execution["ExecutionStartTime"], execution

    listed_after = ssm.describe_automation_executions(
        Filters=[{"Key": "ExecutionId", "Values": [execution_id]}]
    )["AutomationExecutionMetadataList"]
    assert listed_after[0]["AutomationExecutionStatus"] == "Cancelled", listed_after[0]

    steps_after = ssm.describe_automation_step_executions(
        AutomationExecutionId=execution_id
    )["StepExecutions"]
    sleep_step = next(s for s in steps_after if s["StepName"] == "sleepStep")
    assert sleep_step["StepStatus"] in ("Cancelled", "Failed", "TimedOut"), sleep_step


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
