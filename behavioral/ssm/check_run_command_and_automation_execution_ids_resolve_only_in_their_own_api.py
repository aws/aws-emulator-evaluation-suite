"""run-command-and-automation-execution-ids-resolve-only-in-their-own-api."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "run-command-and-automation-execution-ids-resolve-only-in-their-own-api"
GROUP = "state-machine"
SERVICES = ["ssm"]

_MARK = [{"Key": "sim2real", "Value": CHECK}]
_TERMINAL = ("Success", "Failed", "Cancelled", "TimedOut")

#: GetAutomationExecution on an id that names no automation execution.
_NO_EXECUTION = (
    "AutomationExecutionNotFoundException",
    "The input automation execution does not exist.",
)
#: CancelCommand on an id that names no command; {id} is the id sent.
_NO_COMMAND = ("InvalidCommandId", "Command id {id} does not exist.")

_DOC = json.dumps(
    {
        "schemaVersion": "0.3",
        "description": "sim2real-behav one-step automation",
        "mainSteps": [
            {
                "name": "pause",
                "action": "aws:sleep",
                "isEnd": True,
                "inputs": {"Duration": "PT1S"},
            }
        ],
    }
)


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A Run Command id and an Automation execution id differ and resolve only in their own API.

    GetAutomationExecution refuses the command id; CancelCommand refuses the execution id.
    """
    ssm = ctx.client("ssm")

    doc_name = ctx.unique_name("sim2real-behav-idspace-")
    ctx.on_cleanup(lambda: _delete_document(ssm, doc_name))
    ssm.create_document(
        Name=doc_name, DocumentType="Automation", DocumentFormat="JSON", Content=_DOC, Tags=_MARK
    )
    _poll(
        ctx,
        lambda: ssm.describe_document(Name=doc_name)["Document"]["Status"],
        lambda status: status == "Active",
        description="the created Automation document becomes Active",
    )

    command_id = _with_retry(
        ctx,
        lambda: ssm.send_command(
            DocumentName="AWS-RunShellScript",
            Targets=[
                {"Key": "tag:" + ctx.unique_name("nomatch-"), "Values": [ctx.unique_name("v-")]}
            ],
            Parameters={"commands": ["echo id-space"]},
        ),
    )["Command"]["CommandId"]
    execution_id = ssm.start_automation_execution(DocumentName=doc_name)["AutomationExecutionId"]

    # Positive controls: each id resolves in its own API.
    listed = [c["CommandId"] for c in ssm.list_commands(CommandId=command_id)["Commands"]]
    assert listed == [command_id], (
        f"ListCommands must return exactly the sent command; got {listed!r}"
    )
    final = _poll(
        ctx,
        lambda: ssm.get_automation_execution(AutomationExecutionId=execution_id)[
            "AutomationExecution"
        ],
        lambda e: e["AutomationExecutionStatus"] in _TERMINAL,
        description="the one-step automation reaches a terminal status",
    )
    assert (
        final["AutomationExecutionId"],
        final["DocumentName"],
        final["AutomationExecutionStatus"],
    ) == (execution_id, doc_name, "Success"), (
        f"GetAutomationExecution must report {doc_name!r} at Success; got {final!r}"
    )

    as_execution = _refused(lambda: ssm.get_automation_execution(AutomationExecutionId=command_id))
    assert as_execution == _NO_EXECUTION, (
        f"a Run Command id is not an automation execution, so GetAutomationExecution must refuse "
        f"it with exactly {_NO_EXECUTION!r}; got {as_execution!r}"
    )
    expected_command = (_NO_COMMAND[0], _NO_COMMAND[1].format(id=execution_id))
    as_command = _refused(lambda: ssm.cancel_command(CommandId=execution_id))
    assert as_command == expected_command, (
        f"an automation execution id is not a command, so CancelCommand must refuse it with "
        f"exactly {expected_command!r}; got {as_command!r}"
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, less than the runner's remaining time so the poll fails first."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(ctx, probe, predicate, *, description, cap_s=120.0, interval_s=2.0):
    timeout_s = _budget_s(ctx, cap_s)
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"run budget ended while waiting: {description}")
            raise AssertionError(f"{description} not within {timeout_s:.0f}s; last {last!r}")
        time.sleep(interval_s)
        last = probe()
    return last


def _with_retry(ctx, fn, retries=10, delay=3.0):
    """Retry a throttled call while the run has time left; SendCommand throttles bursts."""
    last = None
    for _ in range(retries):
        left = ctx.time_left()
        if last is not None and left is not None and left < 10.0:
            break
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in (
                "TooManyUpdates",
                "ThrottlingException",
            ):
                time.sleep(delay)
                continue
            raise
    raise last


def _refused(fn):
    """``(code, message)`` of a call that must be refused; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _delete_document(ssm, name):
    try:
        ssm.delete_document(Name=name, Force=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidDocument":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
