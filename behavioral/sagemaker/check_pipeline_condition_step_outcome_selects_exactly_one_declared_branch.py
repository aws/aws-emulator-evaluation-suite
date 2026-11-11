"""pipeline-condition-step-outcome-selects-exactly-one-declared-branch."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "pipeline-condition-step-outcome-selects-exactly-one-declared-branch"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

_CONDITION_STEP = "Branch"
_IF_STEP = "TookIfBranch"
_ELSE_STEP = "TookElseBranch"
#: The value the condition compares Parameters.Gate against.
_GATE_TRUE = "yes"
_GATE_FALSE = "no"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Pipelines condition step selects exactly one branch: two executions differing only in a
    parameter report opposite Condition.Outcome values, run only their own branch's Fail step (the
    untaken step is absent), and that step's ErrorMessage is the resolved parameter value."""
    sm = ctx.client("sagemaker")
    role_arn = _create_pipeline_role(ctx)

    # Per-run unique markers prove the executor resolved {"Get": "Parameters.X"} in the taken branch.
    if_marker = ctx.unique_name("if-branch-")
    else_marker = ctx.unique_name("else-branch-")
    pipeline_name = _create_pipeline(ctx, role_arn)

    # Two executions differing only in Parameters.Gate; each is the other's control.
    true_arn = _start(sm, pipeline_name, _GATE_TRUE, if_marker, else_marker)
    false_arn = _start(sm, pipeline_name, _GATE_FALSE, if_marker, else_marker)

    shared_deadline = time.monotonic() + _EXECUTION_TIMEOUT_S
    true_exec = _wait_terminal(sm, true_arn, shared_deadline)
    false_exec = _wait_terminal(sm, false_arn, shared_deadline)

    # A Fail step is the only leaf in either branch, so both executions must fail.
    for arn, desc in ((true_arn, true_exec), (false_arn, false_exec)):
        assert desc["PipelineExecutionStatus"] == "Failed", (
            f"{arn}: a branch whose only leaf is a Fail step must fail the execution: expected "
            f"PipelineExecutionStatus='Failed', got {desc['PipelineExecutionStatus']!r}; "
            f"FailureReason={desc.get('FailureReason')!r}"
        )

    true_steps = _steps_by_name(sm, true_arn)
    false_steps = _steps_by_name(sm, false_arn)

    # Outcome values are the ConditionOutcome enum: "True" / "False".
    true_outcome = _condition_outcome(true_steps, true_arn)
    false_outcome = _condition_outcome(false_steps, false_arn)
    assert true_outcome == "True", (
        f"with Parameters.Gate={_GATE_TRUE!r} equal to the condition's RightValue, "
        f"Metadata.Condition.Outcome must be 'True', got {true_outcome!r}"
    )
    assert false_outcome == "False", (
        f"with Parameters.Gate={_GATE_FALSE!r} unequal to the condition's RightValue, "
        f"Metadata.Condition.Outcome must be 'False', got {false_outcome!r}"
    )
    assert true_outcome != false_outcome, (
        f"the two executions differ only in Parameters.Gate, so their condition outcomes must "
        f"differ; both are {true_outcome!r}"
    )

    # ListPipelineExecutionSteps lists only steps that ran: the untaken step is absent.
    assert set(true_steps) == {_CONDITION_STEP, _IF_STEP}, (
        f"the Outcome=True execution must run the condition step and ONLY the if-branch: expected "
        f"steps {{{_CONDITION_STEP!r}, {_IF_STEP!r}}}, got {sorted(true_steps)}"
    )
    assert set(false_steps) == {_CONDITION_STEP, _ELSE_STEP}, (
        f"the Outcome=False execution must run the condition step and ONLY the else-branch: "
        f"expected steps {{{_CONDITION_STEP!r}, {_ELSE_STEP!r}}}, got {sorted(false_steps)}"
    )
    assert _ELSE_STEP not in true_steps, (
        f"the untaken else-branch step {_ELSE_STEP!r} must not appear in the Outcome=True "
        f"execution's steps: {sorted(true_steps)}"
    )
    assert _IF_STEP not in false_steps, (
        f"the untaken if-branch step {_IF_STEP!r} must not appear in the Outcome=False "
        f"execution's steps: {sorted(false_steps)}"
    )

    for label, steps, leaf in (("true", true_steps, _IF_STEP), ("false", false_steps, _ELSE_STEP)):
        cond_status = steps[_CONDITION_STEP]["StepStatus"]
        leaf_status = steps[leaf]["StepStatus"]
        assert cond_status == "Succeeded", (
            f"{label} execution: the condition step must SUCCEED at evaluating (the failure "
            f"belongs to the branch leaf): expected StepStatus='Succeeded' on "
            f"{_CONDITION_STEP!r}, got {cond_status!r}"
        )
        assert leaf_status == "Failed", (
            f"{label} execution: the Fail step {leaf!r} must report StepStatus='Failed', got "
            f"{leaf_status!r}"
        )
        start, end = steps[leaf]["StartTime"], steps[leaf]["EndTime"]
        assert steps[_CONDITION_STEP]["EndTime"] <= start, (
            f"{label} execution: the branch leaf must start no earlier than the condition step "
            f"finished evaluating: condition ended "
            f"{steps[_CONDITION_STEP]['EndTime'].isoformat()}, leaf started {start.isoformat()}"
        )
        assert end >= start, (
            f"{label} execution: step {leaf!r} ends before it starts: {start.isoformat()} -> "
            f"{end.isoformat()}"
        )

    taken_if = true_steps[_IF_STEP]["Metadata"]["Fail"]["ErrorMessage"]
    taken_else = false_steps[_ELSE_STEP]["Metadata"]["Fail"]["ErrorMessage"]
    assert taken_if == if_marker, (
        f"the if-branch Fail step's ErrorMessage must be the RESOLVED value of "
        f"Parameters.IfMarker: expected {if_marker!r}, got {taken_if!r}"
    )
    assert taken_else == else_marker, (
        f"the else-branch Fail step's ErrorMessage must be the RESOLVED value of "
        f"Parameters.ElseMarker: expected {else_marker!r}, got {taken_else!r}"
    )
    assert taken_if != taken_else, (
        f"the two branches declare different markers, so their resolved ErrorMessages must "
        f"differ; both are {taken_if!r}"
    )


import json  # noqa: E402
import time  # noqa: E402

from botocore.exceptions import ClientError  # noqa: E402

#: Shared across both concurrent executions; there is no compute to provision.
_EXECUTION_TIMEOUT_S = 240.0
#: Bounded window for IAM role propagation to SageMaker.
_IAM_PROPAGATION_TIMEOUT_S = 120.0


def _definition() -> str:
    """The pipeline definition: one Condition step (Equals on Parameters.Gate) whose If and Else
    branches are each a single Fail step."""
    return json.dumps({
        "Version": "2020-12-01",
        "Parameters": [
            {"Name": "Gate", "Type": "String", "DefaultValue": _GATE_FALSE},
            {"Name": "IfMarker", "Type": "String", "DefaultValue": "unset-if"},
            {"Name": "ElseMarker", "Type": "String", "DefaultValue": "unset-else"},
        ],
        "Steps": [{
            "Name": _CONDITION_STEP,
            "Type": "Condition",
            "Arguments": {
                "Conditions": [{
                    "Type": "Equals",
                    "LeftValue": {"Get": "Parameters.Gate"},
                    "RightValue": _GATE_TRUE,
                }],
                "IfSteps": [{
                    "Name": _IF_STEP,
                    "Type": "Fail",
                    "Arguments": {"ErrorMessage": {"Get": "Parameters.IfMarker"}},
                }],
                "ElseSteps": [{
                    "Name": _ELSE_STEP,
                    "Type": "Fail",
                    "Arguments": {"ErrorMessage": {"Get": "Parameters.ElseMarker"}},
                }],
            },
        }],
    })


def _create_pipeline_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-smpc-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_pipeline(ctx, role_arn: str) -> str:
    sm = ctx.client("sagemaker")
    pipeline_name = ctx.unique_name("sim2real-smpc-pl-")
    definition = _definition()
    deadline = time.monotonic() + _IAM_PROPAGATION_TIMEOUT_S
    while True:
        try:
            sm.create_pipeline(
                PipelineName=pipeline_name,
                PipelineDefinition=definition,
                RoleArn=role_arn,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            break
        except ClientError as exc:
            msg = str(exc)
            transient = (
                "AccessDenied" in msg or "cannot be assumed" in msg or "not authorized" in msg
            )
            if not transient or time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreatePipeline did not succeed within {_IAM_PROPAGATION_TIMEOUT_S}s of role "
                    f"creation; last error: {exc}"
                ) from exc
            time.sleep(5)
    ctx.on_cleanup(lambda: sm.delete_pipeline(PipelineName=pipeline_name))

    # Check the stored definition first, so a later branch failure cannot be blamed on it.
    stored = json.loads(
        sm.describe_pipeline(PipelineName=pipeline_name)["PipelineDefinition"]
    )
    step_names = [s["Name"] for s in stored["Steps"]]
    assert step_names == [_CONDITION_STEP], (
        f"DescribePipeline must round-trip exactly the one top-level step declared: expected "
        f"[{_CONDITION_STEP!r}], got {step_names}"
    )
    branches = stored["Steps"][0]["Arguments"]
    assert [s["Name"] for s in branches["IfSteps"]] == [_IF_STEP], (
        f"the stored definition must keep the if-branch: got {branches.get('IfSteps')}"
    )
    assert [s["Name"] for s in branches["ElseSteps"]] == [_ELSE_STEP], (
        f"the stored definition must keep the else-branch: got {branches.get('ElseSteps')}"
    )
    return pipeline_name


def _start(sm, pipeline_name: str, gate: str, if_marker: str, else_marker: str) -> str:
    resp = sm.start_pipeline_execution(
        PipelineName=pipeline_name,
        PipelineParameters=[
            {"Name": "Gate", "Value": gate},
            {"Name": "IfMarker", "Value": if_marker},
            {"Name": "ElseMarker", "Value": else_marker},
        ],
    )
    return resp["PipelineExecutionArn"]


def _wait_terminal(sm, arn: str, deadline: float) -> dict:
    """Poll to a terminal PipelineExecutionStatus against a shared deadline; raise on timeout."""
    last = None
    while time.monotonic() < deadline:
        last = sm.describe_pipeline_execution(PipelineExecutionArn=arn)
        if last["PipelineExecutionStatus"] in ("Succeeded", "Failed", "Stopped"):
            return last
        time.sleep(5)
    raise AssertionError(
        f"pipeline execution {arn} did not reach a terminal status within the shared "
        f"{_EXECUTION_TIMEOUT_S}s budget; last status "
        f"{last['PipelineExecutionStatus'] if last else 'unknown'}"
    )


def _steps_by_name(sm, arn: str) -> dict:
    """Map step name to step via ListPipelineExecutionSteps; a duplicate name fails."""
    steps: list = []
    token = None
    while True:
        kwargs = {"PipelineExecutionArn": arn, "MaxResults": 100}
        if token:
            kwargs["NextToken"] = token
        page = sm.list_pipeline_execution_steps(**kwargs)
        steps.extend(page["PipelineExecutionSteps"])
        token = page.get("NextToken")
        if not token:
            break
    by_name: dict = {}
    for s in steps:
        name = s["StepName"]
        assert name not in by_name, (
            f"{arn}: step {name!r} appears more than once in ListPipelineExecutionSteps"
        )
        by_name[name] = s
    return by_name


def _condition_outcome(steps: dict, arn: str) -> str:
    """Return the condition step's Metadata.Condition.Outcome, asserting each level is present."""
    assert _CONDITION_STEP in steps, (
        f"{arn}: the condition step {_CONDITION_STEP!r} must appear in the executed steps; got "
        f"{sorted(steps)}"
    )
    metadata = steps[_CONDITION_STEP]["Metadata"]
    assert "Condition" in metadata, (
        f"{arn}: a Condition step's Metadata must carry a 'Condition' member; got "
        f"{sorted(metadata)}"
    )
    return metadata["Condition"]["Outcome"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
