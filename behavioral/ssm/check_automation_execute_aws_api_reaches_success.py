"""automation-execute-aws-api-reaches-success."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "automation-execute-aws-api-reaches-success"
GROUP = 'state-machine'
SERVICES = ['ssm']

_TERMINAL = ("Success", "Failed", "Cancelled", "TimedOut")
_SOURCE_VALUE = "sim2real-behav-automation-input"


def _error_code(fn):
    """Return the ClientError (code, message) raised by fn; an unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _track_parameter(ctx, ssm, name):
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    return name


def _call_with_retry(fn, retries=10, delay=2.0):
    last = None
    for _ in range(retries):
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


def _poll(probe, predicate, timeout_s=180, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _automation_doc():
    return json.dumps(
        {
            "schemaVersion": "0.3",
            "description": "sim2real-behav agentless automation: read a parameter, pause, write it back",
            "parameters": {
                "SourceName": {"type": "String", "description": "parameter to read"},
                "TargetName": {"type": "String", "description": "parameter to write"},
            },
            "outputs": ["readParam.Value"],
            "mainSteps": [
                {
                    "name": "readParam",
                    "action": "aws:executeAwsApi",
                    "nextStep": "pauseBriefly",
                    "isEnd": False,
                    "inputs": {
                        "Service": "ssm",
                        "Api": "GetParameter",
                        "Name": "{{SourceName}}",
                    },
                    "outputs": [
                        {
                            "Name": "Value",
                            "Selector": "$.Parameter.Value",
                            "Type": "String",
                        }
                    ],
                },
                {
                    "name": "pauseBriefly",
                    "action": "aws:sleep",
                    "nextStep": "writeParam",
                    "isEnd": False,
                    "inputs": {"Duration": "PT1S"},
                },
                {
                    "name": "writeParam",
                    "action": "aws:executeAwsApi",
                    "isEnd": True,
                    "inputs": {
                        "Service": "ssm",
                        "Api": "PutParameter",
                        "Name": "{{TargetName}}",
                        "Value": "{{readParam.Value}}-echo",
                        "Type": "String",
                        "Overwrite": True,
                    },
                },
            ],
        }
    )


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An aws:executeAwsApi Automation runs its steps to Success in order with parameter and
    step-output substitution, projects its outputs, and really writes the target parameter;
    an unknown document or execution and a missing required parameter are refused."""

    ssm = ctx.client("ssm")

    source = _param_name(ctx, "auto-src-")
    target = _param_name(ctx, "auto-dst-")
    _track_parameter(ctx, ssm, source)
    # Registered before the automation runs: the automation is what creates it.
    _track_parameter(ctx, ssm, target)

    ssm.put_parameter(
        Name=source,
        Value=_SOURCE_VALUE,
        Type="String",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    # AWS sends ParameterNotFound with an empty message.
    assert _error_code(lambda: ssm.get_parameter(Name=target)) == ("ParameterNotFound", ""), (
        "the target parameter must not exist before the automation runs"
    )

    doc_name = ctx.unique_name("sim2real-behav-auto-")
    ssm.create_document(
        Name=doc_name,
        DocumentType="Automation",
        DocumentFormat="JSON",
        Content=_automation_doc(),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=doc_name, Force=True))
    _poll(
        lambda: ssm.describe_document(Name=doc_name)["Document"],
        lambda d: d.get("Status") == "Active",
        timeout_s=120,
        interval_s=3.0,
    )

    started = _call_with_retry(
        lambda: ssm.start_automation_execution(
            DocumentName=doc_name,
            Parameters={"SourceName": [source], "TargetName": [target]},
        )
    )
    execution_id = started["AutomationExecutionId"]
    assert execution_id, started

    final = _poll(
        lambda: ssm.get_automation_execution(AutomationExecutionId=execution_id)[
            "AutomationExecution"
        ],
        lambda e: e.get("AutomationExecutionStatus") in _TERMINAL,
    )
    assert final["AutomationExecutionStatus"] == "Success", (
        "the automation must reach Success; got "
        f"{final['AutomationExecutionStatus']!r} / {final.get('FailureMessage')!r}"
    )
    assert final["DocumentName"] == doc_name, final
    assert final["ExecutionEndTime"] >= final["ExecutionStartTime"], (
        f"ExecutionEndTime {final['ExecutionEndTime']} precedes ExecutionStartTime "
        f"{final['ExecutionStartTime']}"
    )

    # --- document-level outputs projection ----------------------------------
    outputs = final.get("Outputs") or {}
    assert "readParam.Value" in outputs, (
        "the document declares outputs ['readParam.Value']; GetAutomationExecution must "
        f"project it, got keys {sorted(outputs)}"
    )
    assert outputs["readParam.Value"] == [_SOURCE_VALUE], (
        "the projected output must be the value the step actually read, got "
        f"{outputs['readParam.Value']!r}"
    )

    # --- step executions: all three, all Success, strictly sequential -------
    steps = ssm.describe_automation_step_executions(
        AutomationExecutionId=execution_id
    )["StepExecutions"]
    by_name = {s["StepName"]: s for s in steps}
    assert set(by_name) == {"readParam", "pauseBriefly", "writeParam"}, (
        f"all three declared steps must appear, got {sorted(by_name)}"
    )
    assert len(steps) == 3, f"expected exactly 3 step executions, got {len(steps)}"
    for step_name, step in by_name.items():
        assert step["StepStatus"] == "Success", (
            f"step {step_name} must be Success, got {step['StepStatus']!r} / "
            f"{step.get('FailureMessage')!r}"
        )
    assert by_name["readParam"]["Action"] == "aws:executeAwsApi", by_name["readParam"]
    assert by_name["pauseBriefly"]["Action"] == "aws:sleep", by_name["pauseBriefly"]
    assert by_name["writeParam"]["Action"] == "aws:executeAwsApi", by_name["writeParam"]

    order = ["readParam", "pauseBriefly", "writeParam"]
    for earlier, later in zip(order, order[1:]):
        assert (
            by_name[earlier]["ExecutionEndTime"] <= by_name[later]["ExecutionStartTime"]
        ), (
            f"steps must run sequentially: {earlier} ended at "
            f"{by_name[earlier]['ExecutionEndTime']} but {later} started at "
            f"{by_name[later]['ExecutionStartTime']}"
        )
    assert by_name["writeParam"]["IsEnd"] is True, (
        f"writeParam is declared isEnd; got {by_name['writeParam'].get('IsEnd')!r}"
    )

    # The step's own output must carry the value it selected out of the response.
    read_outputs = by_name["readParam"].get("Outputs") or {}
    assert read_outputs.get("Value") == [_SOURCE_VALUE], (
        "the readParam step's Selector $.Parameter.Value must yield the parameter value, "
        f"got {read_outputs!r}"
    )

    # --- observe the effect: the second API step really wrote the parameter --
    written = _poll(
        lambda: ssm.get_parameter(Name=target)["Parameter"],
        lambda p: p.get("Value") == f"{_SOURCE_VALUE}-echo",
        timeout_s=60,
        interval_s=3.0,
    )
    assert written["Value"] == f"{_SOURCE_VALUE}-echo", (
        "the writeParam step must have created the target parameter with the substituted "
        f"value; got {written['Value']!r}"
    )
    assert written["Version"] == 1, (
        f"the automation must have created the target exactly once, got {written}"
    )
    assert written["Type"] == "String", written

    # --- the execution is also findable by list, and agrees ------------------
    listed = ssm.describe_automation_executions(
        Filters=[
            {"Key": "ExecutionId", "Values": [execution_id]},
        ]
    )["AutomationExecutionMetadataList"]
    assert len(listed) == 1, (
        f"the execution must be findable by ExecutionId filter, got {listed}"
    )
    assert listed[0]["AutomationExecutionStatus"] == "Success", listed[0]
    assert listed[0]["DocumentName"] == doc_name, listed[0]

    # --- negatives: unknown document, and unknown execution id --------------
    unknown_doc = _error_code(
        lambda: ssm.start_automation_execution(DocumentName="sim2real-behav-no-such-automation")
    )
    assert unknown_doc == (
        "AutomationDefinitionNotFoundException",
        "Invalid input for field document name, expected valid document in account.",
    ), f"starting an unknown automation must be refused, got {unknown_doc!r}"
    unknown_execution = _error_code(
        lambda: ssm.get_automation_execution(
            AutomationExecutionId="00000000-0000-0000-0000-000000000000"
        )
    )
    assert unknown_execution == (
        "AutomationExecutionNotFoundException",
        "The input automation execution does not exist.",
    ), f"an unknown execution id must be refused, got {unknown_execution!r}"
    # A required document parameter omitted must be refused before anything runs.
    missing_param = _error_code(
        lambda: ssm.start_automation_execution(
            DocumentName=doc_name, Parameters={"SourceName": [source]}
        )
    )
    assert missing_param == (
        "InvalidAutomationExecutionParametersException",
        "Missing required parameter: TargetName in user inputs.",
    ), f"omitting the required TargetName parameter must be refused, got {missing_param!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
