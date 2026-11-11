"""ssm-automation-branch-takes-one-path-and-the-other-branchs-effect-is-absent."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ssm-automation-branch-takes-one-path-and-the-other-branchs-effect-is-absent"
GROUP = 'automation'
SERVICES = ['ssm']

_TERMINAL = ("Success", "Failed", "Cancelled", "TimedOut")


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
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


def _automation_doc():
    """One document, two mutually exclusive terminal steps, routed by aws:branch."""
    return json.dumps(
        {
            "schemaVersion": "0.3",
            "description": (
                "sim2real-behav: aws:branch routes to exactly one of two "
                "parameter-writing steps"
            ),
            "parameters": {
                "Which": {"type": "String", "description": "left or right"},
                "LeftName": {"type": "String", "description": "parameter the LEFT step writes"},
                "RightName": {
                    "type": "String",
                    "description": "parameter the RIGHT step writes",
                },
            },
            "mainSteps": [
                {
                    "name": "branch",
                    "action": "aws:branch",
                    "inputs": {
                        "Choices": [
                            {
                                "NextStep": "LEFT",
                                "Variable": "{{Which}}",
                                "StringEquals": "left",
                            },
                            {
                                "NextStep": "RIGHT",
                                "Variable": "{{Which}}",
                                "StringEquals": "right",
                            },
                        ]
                    },
                },
                {
                    "name": "LEFT",
                    "action": "aws:executeAwsApi",
                    "isEnd": True,
                    "inputs": {
                        "Service": "ssm",
                        "Api": "PutParameter",
                        "Name": "{{LeftName}}",
                        "Value": "took-left",
                        "Type": "String",
                        "Overwrite": True,
                    },
                },
                {
                    "name": "RIGHT",
                    "action": "aws:executeAwsApi",
                    "isEnd": True,
                    "inputs": {
                        "Service": "ssm",
                        "Api": "PutParameter",
                        "Name": "{{RightName}}",
                        "Value": "took-right",
                        "Type": "String",
                        "Overwrite": True,
                    },
                },
            ],
        }
    )


@tags(
    "axis:rejection",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """aws:branch runs exactly one of two exclusive steps: the taken step's parameter exists and the
    untaken one's does not, inverting the input inverts it, and an unmatched input falls through.
    """

    ssm = ctx.client("ssm")

    # Four parameter names, one fresh pair per directional run. All four cleanups
    # are registered before any execution starts: the automation is what creates
    # them, so a failed poll must not be able to strand one.
    left_1 = _param_name(ctx, "branch-l1-")
    right_1 = _param_name(ctx, "branch-r1-")
    left_2 = _param_name(ctx, "branch-l2-")
    right_2 = _param_name(ctx, "branch-r2-")
    none_left = _param_name(ctx, "branch-nl-")
    none_right = _param_name(ctx, "branch-nr-")
    for name in (left_1, right_1, left_2, right_2, none_left, none_right):
        _track_parameter(ctx, ssm, name)
        _assert_parameter_absent(ssm, name, f"{name!r} must not exist before the automation runs")

    doc_name = ctx.unique_name("sim2real-behav-auto-branch-")
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

    def _execute(which, left, right):
        started = _call_with_retry(
            lambda: ssm.start_automation_execution(
                DocumentName=doc_name,
                Parameters={
                    "Which": [which],
                    "LeftName": [left],
                    "RightName": [right],
                },
            )
        )
        final = _poll(
            lambda: ssm.get_automation_execution(
                AutomationExecutionId=started["AutomationExecutionId"]
            )["AutomationExecution"],
            lambda e: e.get("AutomationExecutionStatus") in _TERMINAL,
            timeout_s=180,
            interval_s=5.0,
        )
        steps = ssm.describe_automation_step_executions(
            AutomationExecutionId=started["AutomationExecutionId"]
        )["StepExecutions"]
        return final, [(s["StepName"], s["StepStatus"]) for s in steps]

    # --- leg 1: Which=left. Unreached steps stay listed as Pending rather than being omitted.
    left_run, left_steps = _execute("left", left_1, right_1)
    assert left_run["AutomationExecutionStatus"] == "Success", (
        "the Which=left execution must reach Success; got "
        f"{left_run['AutomationExecutionStatus']!r} / {left_run.get('FailureMessage')!r}"
    )
    taken = _poll(
        lambda: ssm.get_parameter(Name=left_1)["Parameter"],
        lambda p: p.get("Value") == "took-left",
        timeout_s=60,
        interval_s=3.0,
    )
    # Positive control for the absence assertion below: the taken branch really
    # wrote its own parameter, so an absent RIGHT is routing, not a broken document.
    assert taken["Value"] == "took-left", (
        f"the LEFT step must have written {left_1!r} with 'took-left', got {taken['Value']!r}"
    )
    _assert_parameter_absent(
        ssm,
        right_1,
        f"the untaken RIGHT branch left a parameter behind: {right_1!r} exists after a "
        "Which=left execution",
    )
    assert left_steps == [
        ("branch", "Success"),
        ("LEFT", "Success"),
        ("RIGHT", "Pending"),
    ], (
        "every declared step is enumerated, but only the selected one may leave Pending: "
        f"got {left_steps!r}"
    )

    # --- leg 2: the same document, Which=right, fresh names. Steps are listed in execution order.
    right_run, right_steps = _execute("right", left_2, right_2)
    assert right_run["AutomationExecutionStatus"] == "Success", (
        "the Which=right execution must reach Success; got "
        f"{right_run['AutomationExecutionStatus']!r} / {right_run.get('FailureMessage')!r}"
    )
    taken_2 = _poll(
        lambda: ssm.get_parameter(Name=right_2)["Parameter"],
        lambda p: p.get("Value") == "took-right",
        timeout_s=60,
        interval_s=3.0,
    )
    assert taken_2["Value"] == "took-right", (
        f"the RIGHT step must have written {right_2!r} with 'took-right', got "
        f"{taken_2['Value']!r}"
    )
    _assert_parameter_absent(
        ssm,
        left_2,
        f"the untaken LEFT branch left a parameter behind: {left_2!r} exists after a "
        "Which=right execution",
    )
    assert right_steps == [
        ("branch", "Success"),
        ("RIGHT", "Success"),
        ("LEFT", "Pending"),
    ], (
        "the mirror of the first leg: RIGHT succeeds and is reported in EXECUTION order "
        f"ahead of the still-Pending LEFT; got {right_steps!r}"
    )

    # The two legs must not have produced the same step list, or the branch is a
    # no-op that always runs whatever comes first.
    assert left_steps != right_steps, (
        "inverting the input must change which step runs; both legs executed "
        f"{left_steps!r}"
    )

    # --- leg 3: an input matching no Choice, with no Default declared --------
    none_run, none_steps = _execute("neither", none_left, none_right)
    # With no matching Choice and no Default, AWS reaches Success and falls through to the step
    # declared after the branch, so LEFT runs and RIGHT stays Pending.
    assert none_run["AutomationExecutionStatus"] == "Success", (
        "aws:branch with no matching Choice and no Default ends the execution "
        "successfully on real AWS; got "
        f"{none_run['AutomationExecutionStatus']!r} / {none_run.get('FailureMessage')!r}"
    )
    assert none_steps == [
        ("branch", "Success"),
        ("LEFT", "Success"),
        ("RIGHT", "Pending"),
    ], (
        "an unmatched branch falls through to the NEXT DECLARED step (LEFT), and only "
        f"that one; got {none_steps!r}"
    )
    fell_through = _poll(
        lambda: ssm.get_parameter(Name=none_left)["Parameter"],
        lambda p: p.get("Value") == "took-left",
        timeout_s=60,
        interval_s=3.0,
    )
    assert fell_through["Value"] == "took-left", (
        "the fall-through must really execute the next declared step, so "
        f"{none_left!r} must hold 'took-left'; got {fell_through['Value']!r}"
    )
    # Exclusivity survives the fall-through: the step AFTER the one fallen into is
    # still never reached, because LEFT is isEnd.
    _assert_parameter_absent(
        ssm,
        none_right,
        f"{none_right!r} exists, so the fall-through ran past the isEnd step it landed "
        "on and executed RIGHT as well",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
