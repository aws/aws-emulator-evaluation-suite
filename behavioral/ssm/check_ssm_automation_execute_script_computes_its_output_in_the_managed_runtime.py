"""ssm-automation-execute-script-computes-its-output-in-the-managed-runtime."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ssm-automation-execute-script-computes-its-output-in-the-managed-runtime"
GROUP = 'automation'
SERVICES = ['ssm']

_TERMINAL = ("Success", "Failed", "Cancelled", "TimedOut")
_SEED = 37
_DECLARED_RUNTIME = "python3.11"


def _error(fn):
    """Return the botocore error (code, message) fn raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _assert_parameter_absent(ssm, name, why):
    """GetParameter on name must be refused as ParameterNotFound with AWS's exact message."""
    code, message = _error(lambda: ssm.get_parameter(Name=name))
    assert code == "ParameterNotFound", f"{why}: got {code!r}"
    assert message == "", message


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _track_parameter(ctx, ssm, name):
    # The automation may never create name (an untaken branch, a failed step), so the
    # teardown tolerates ParameterNotFound.
    def _delete():
        try:
            ssm.delete_parameter(Name=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
                raise

    ctx.on_cleanup(_delete)
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


# Every field of the return value requires actually running Python:
#   value    -- arithmetic on the substituted InputPayload
#   items    -- an ordered StringList
#   count    -- an Integer-typed output
#   runtime  -- the interpreter version of the runtime SSM was asked to use
_SCRIPT = '''
import platform


def handler(events, context):
    seed = int(events["seed"])
    return {
        "value": str(seed * 11),
        "items": ["a", "b", "c"],
        "count": seed % 7,
        "runtime": platform.python_version(),
    }
'''


def _automation_doc():
    return json.dumps(
        {
            "schemaVersion": "0.3",
            "description": (
                "sim2real-behav: aws:executeScript computes a payload in SSM's managed "
                "runtime and a later step persists it"
            ),
            "parameters": {
                "Seed": {"type": "String", "description": "the number the script multiplies"},
                "TargetName": {"type": "String", "description": "parameter to write"},
            },
            "outputs": [
                "compute.value",
                "compute.items",
                "compute.count",
                "compute.runtime",
            ],
            "mainSteps": [
                {
                    "name": "compute",
                    "action": "aws:executeScript",
                    "nextStep": "persist",
                    "isEnd": False,
                    "inputs": {
                        "Runtime": _DECLARED_RUNTIME,
                        "Handler": "handler",
                        "InputPayload": {"seed": "{{Seed}}"},
                        "Script": _SCRIPT,
                    },
                    "outputs": [
                        {"Name": "value", "Selector": "$.Payload.value", "Type": "String"},
                        {
                            "Name": "items",
                            "Selector": "$.Payload.items",
                            "Type": "StringList",
                        },
                        {"Name": "count", "Selector": "$.Payload.count", "Type": "Integer"},
                        {
                            "Name": "runtime",
                            "Selector": "$.Payload.runtime",
                            "Type": "String",
                        },
                    ],
                },
                {
                    "name": "persist",
                    "action": "aws:executeAwsApi",
                    "isEnd": True,
                    "inputs": {
                        "Service": "ssm",
                        "Api": "PutParameter",
                        "Name": "{{TargetName}}",
                        "Value": "{{compute.value}}",
                        "Type": "String",
                        "Overwrite": True,
                    },
                },
            ],
        }
    )


@tags("axis:happy-path", "concern:data-plane", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """aws:executeScript runs Python in the declared python3.11 runtime: its typed outputs, the
    step Outputs and a parameter written by a later step all carry the computed value; an
    unsatisfiable Selector fails the execution and the later step never runs.
    """

    ssm = ctx.client("ssm")

    target = _param_name(ctx, "auto-script-dst-")
    # Registered before the automation runs: the automation is what creates it.
    _track_parameter(ctx, ssm, target)
    _assert_parameter_absent(
        ssm, target, f"the target parameter {target!r} must not exist before the automation runs"
    )

    doc_name = ctx.unique_name("sim2real-behav-auto-script-")
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
            Parameters={"Seed": [str(_SEED)], "TargetName": [target]},
        )
    )
    execution_id = started["AutomationExecutionId"]
    assert execution_id, started

    final = _poll(
        lambda: ssm.get_automation_execution(AutomationExecutionId=execution_id)[
            "AutomationExecution"
        ],
        lambda e: e.get("AutomationExecutionStatus") in _TERMINAL,
        timeout_s=180,
        interval_s=5.0,
    )
    assert final["AutomationExecutionStatus"] == "Success", (
        "the aws:executeScript automation must reach Success; got "
        f"{final['AutomationExecutionStatus']!r} / {final.get('FailureMessage')!r}"
    )

    expected_value = str(_SEED * 11)
    expected_items = ["a", "b", "c"]
    expected_count = _SEED % 7

    # --- document-level outputs projection of the script's return value -----
    outputs = final.get("Outputs") or {}
    assert outputs.get("compute.value") == [expected_value], (
        "the script's String output must project the value it computed from the "
        f"substituted InputPayload; got {outputs.get('compute.value')!r}, expected "
        f"{[expected_value]!r}"
    )
    assert outputs.get("compute.items") == expected_items, (
        "the StringList output must project every element in order; got "
        f"{outputs.get('compute.items')!r}, expected {expected_items!r}"
    )
    assert outputs.get("compute.count") == [str(expected_count)], (
        "the Integer output must project the computed remainder; got "
        f"{outputs.get('compute.count')!r}, expected {[str(expected_count)]!r}"
    )

    # --- the script really ran in the runtime the document declared ---------
    projected_runtime = outputs.get("compute.runtime") or []
    assert len(projected_runtime) == 1, (
        f"exactly one runtime version must be projected, got {projected_runtime!r}"
    )
    assert projected_runtime[0].startswith("3.11."), (
        "the step declares Runtime=python3.11, so platform.python_version() inside the "
        f"managed runtime must begin with '3.11.'; got {projected_runtime[0]!r} — an "
        "emulator that never ran the script cannot report a real interpreter version"
    )

    # --- step executions: both steps, in order, with the declared action ----
    steps = ssm.describe_automation_step_executions(
        AutomationExecutionId=execution_id
    )["StepExecutions"]
    assert [s["StepName"] for s in steps] == ["compute", "persist"], (
        "both declared steps must have executed, in order; got "
        f"{[(s['StepName'], s['StepStatus']) for s in steps]!r}"
    )
    by_name = {s["StepName"]: s for s in steps}
    for step_name, step in by_name.items():
        assert step["StepStatus"] == "Success", (
            f"step {step_name} must be Success, got {step['StepStatus']!r} / "
            f"{step.get('FailureMessage')!r}"
        )
    assert by_name["compute"]["Action"] == "aws:executeScript", by_name["compute"]
    assert by_name["persist"]["Action"] == "aws:executeAwsApi", by_name["persist"]
    assert (
        by_name["compute"]["ExecutionEndTime"]
        <= by_name["persist"]["ExecutionStartTime"]
    ), (
        "persist references {{compute.value}} so it must start only after compute ended: "
        f"compute ended {by_name['compute']['ExecutionEndTime']}, persist started "
        f"{by_name['persist']['ExecutionStartTime']}"
    )

    # The step's OWN Outputs must agree with the document-level projection.
    step_outputs = by_name["compute"].get("Outputs") or {}
    assert step_outputs.get("value") == [expected_value], (
        "the compute step's own Outputs must carry the Selector's result, got "
        f"{step_outputs.get('value')!r}"
    )
    assert step_outputs.get("items") == expected_items, (
        f"the step's StringList output must be ordered and complete, got "
        f"{step_outputs.get('items')!r}"
    )

    # --- observe the effect: the second step consumed the script's output ---
    written = _poll(
        lambda: ssm.get_parameter(Name=target)["Parameter"],
        lambda p: p.get("Value") == expected_value,
        timeout_s=60,
        interval_s=3.0,
    )
    assert written["Value"] == expected_value, (
        "the persist step must have written the value the SCRIPT computed, not the raw "
        f"input; got {written['Value']!r}, expected {expected_value!r}"
    )
    assert written["Version"] == 1, (
        f"the automation must have created the target exactly once, got {written!r}"
    )
    assert written["Type"] == "String", written

    # --- negative: a script whose declared Selector cannot be satisfied -----
    # Breaking exactly one thing (the Selector path) must fail the STEP, and the
    # downstream step that references its output must therefore not run — so the
    # target parameter of the broken document stays absent.
    broken_target = _param_name(ctx, "auto-script-broken-dst-")
    _track_parameter(ctx, ssm, broken_target)
    broken_doc = json.loads(_automation_doc())
    broken_doc["mainSteps"][0]["outputs"][0]["Selector"] = "$.Payload.no_such_field"
    broken_name = ctx.unique_name("sim2real-behav-auto-script-broken-")
    ssm.create_document(
        Name=broken_name,
        DocumentType="Automation",
        DocumentFormat="JSON",
        Content=json.dumps(broken_doc),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ssm.delete_document(Name=broken_name, Force=True))
    _poll(
        lambda: ssm.describe_document(Name=broken_name)["Document"],
        lambda d: d.get("Status") == "Active",
        timeout_s=120,
        interval_s=3.0,
    )
    broken_started = _call_with_retry(
        lambda: ssm.start_automation_execution(
            DocumentName=broken_name,
            Parameters={"Seed": [str(_SEED)], "TargetName": [broken_target]},
        )
    )
    broken_final = _poll(
        lambda: ssm.get_automation_execution(
            AutomationExecutionId=broken_started["AutomationExecutionId"]
        )["AutomationExecution"],
        lambda e: e.get("AutomationExecutionStatus") in _TERMINAL,
        timeout_s=180,
        interval_s=5.0,
    )
    assert broken_final["AutomationExecutionStatus"] == "Failed", (
        "a declared output whose Selector matches nothing in the script's payload must "
        f"fail the execution, got {broken_final['AutomationExecutionStatus']!r} / "
        f"{broken_final.get('FailureMessage')!r}"
    )
    _assert_parameter_absent(
        ssm,
        broken_target,
        "the persist step references the output the compute step failed to produce, so it "
        f"must never have run — but {broken_target!r} exists",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
