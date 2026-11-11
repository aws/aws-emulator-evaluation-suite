"""describe-state-machine-for-execution-labeled-arn-ignores-metadata-only."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-state-machine-for-execution-labeled-arn-ignores-metadata-only"
GROUP = "jsonata"
SERVICES = ["stepfunctions"]


def _create_sfn_role(ctx, sm_arn_for_self_start):
    """A states.amazonaws.com-assumable execution role this check creates and owns, granted
    permission to start, describe and stop executions of its own (not-yet-created) state machine
    so a Distributed Map's child executions can run under it."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-sfnrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]

    def _delete_role():
        for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_delete_role)

    statements = [
        {
            "Effect": "Allow",
            "Action": ["states:StartExecution"],
            "Resource": sm_arn_for_self_start,
        },
        {
            "Effect": "Allow",
            "Action": ["states:DescribeExecution", "states:StopExecution"],
            "Resource": f"{sm_arn_for_self_start.replace(':stateMachine:', ':execution:')}*",
        },
    ]
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=f"{role_name}-policy",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    return role_arn


def _create_state_machine(ctx, role_arn, definition, name):
    """CreateStateMachine, retrying only the AccessDeniedException a freshly created role
    returns until IAM propagates it."""
    sfn = ctx.client("stepfunctions")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type="STANDARD",
                tags=[{"key": "sim2real", "value": "1"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _wait_execution_terminal(sfn, exec_arn, *, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(2.0)
    raise AssertionError(f"execution {exec_arn} not terminal within {timeout_s}s: {last!r}")


_PROPAGATION_MARKERS = (
    "not authorized to assume", "cannot be assumed", "sts:AssumeRole",
    "States.Permissions", "AccessDenied",
)


def _run_to_terminal(ctx, sfn, sm_arn, *, timeout_s, propagation_s=120.0):
    """Start an execution and poll it to terminal, starting a fresh one only when the failure
    is the IAM-propagation race between a just-created role/policy and Step Functions."""
    deadline = time.monotonic() + propagation_s
    while True:
        exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
        ctx.on_cleanup(lambda a=exec_arn: _stop_if_running(sfn, a))
        desc = _wait_execution_terminal(sfn, exec_arn, timeout_s=timeout_s)
        blob = (desc.get("cause") or "") + (desc.get("error") or "")
        if desc["status"] != "FAILED" or not any(m in blob for m in _PROPAGATION_MARKERS):
            return exec_arn, desc
        if time.monotonic() >= deadline:
            return exec_arn, desc
        time.sleep(2)


_MAP_LABEL = "sim2realLabel"


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeStateMachineForExecution on a labeled (Distributed Map child) execution ARN
    carries variableReferences and the full definition for its own ItemProcessor branch, and --
    unlike a plain top-level execution -- includedData=METADATA_ONLY does not suppress either one.
    """
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sm-dmlbl-")
    self_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{name}"
    role_arn = _create_sfn_role(ctx, self_arn)

    definition = {
        "QueryLanguage": "JSONata",
        "StartAt": "Mapper",
        "States": {
            "Mapper": {
                "Type": "Map",
                "Label": _MAP_LABEL,
                "Items": "{% [1, 2] %}",
                "ItemProcessor": {
                    "ProcessorConfig": {"Mode": "DISTRIBUTED", "ExecutionType": "STANDARD"},
                    "StartAt": "Assign",
                    "States": {
                        "Assign": {"Type": "Pass", "Assign": {"w": 1}, "Next": "Use"},
                        "Use": {"Type": "Pass", "Output": {"r": "{% $w %}"}, "End": True},
                    },
                },
                "End": True,
            },
        },
    }
    sm_arn = _create_state_machine(ctx, role_arn, definition, name)
    assert sm_arn == self_arn, f"expected state machine ARN {self_arn!r}, got {sm_arn!r}"

    exec_arn, final = _run_to_terminal(ctx, sfn, sm_arn, timeout_s=90.0)
    assert final["status"] == "SUCCEEDED", (
        f"distributed map execution did not succeed: {final.get('status')} "
        f"error={final.get('error')} cause={final.get('cause')}"
    )

    expected_refs = {"Use": ["w"]}

    # Positive control: the plain top-level execution ARN reports the full definition's variable
    # references (the ItemProcessor's own states included), and METADATA_ONLY behaves exactly as
    # documented: it collapses the definition and drops variableReferences.
    plain_all = sfn.describe_state_machine_for_execution(executionArn=exec_arn)
    assert plain_all.get("variableReferences") == expected_refs, (
        f"positive control: expected variableReferences {expected_refs!r} for the plain "
        f"execution ARN, got {plain_all.get('variableReferences')!r}"
    )
    plain_meta = sfn.describe_state_machine_for_execution(
        executionArn=exec_arn, includedData="METADATA_ONLY"
    )
    assert "variableReferences" not in plain_meta, (
        f"positive control: METADATA_ONLY should drop variableReferences for the plain "
        f"execution ARN, got {plain_meta.get('variableReferences')!r}"
    )
    assert plain_meta["definition"] == "{}", (
        f"positive control: METADATA_ONLY should collapse the definition to '{{}}', "
        f"got {plain_meta['definition']!r}"
    )

    map_runs = sfn.list_map_runs(executionArn=exec_arn)["mapRuns"]
    assert len(map_runs) == 1, f"expected exactly one Map Run, got {map_runs!r}"
    map_run_arn = map_runs[0]["mapRunArn"]

    children = sfn.list_executions(mapRunArn=map_run_arn)["executions"]
    assert len(children) == 2, f"expected 2 child executions (one per item), got {children!r}"
    child_arn = children[0]["executionArn"]
    assert f"/{_MAP_LABEL}:" in child_arn, (
        f"child execution ARN missing the Map Run label {_MAP_LABEL!r}: {child_arn!r}"
    )

    child_all = sfn.describe_state_machine_for_execution(executionArn=child_arn)
    assert child_all.get("label") == _MAP_LABEL, (
        f"expected label {_MAP_LABEL!r} on the labeled execution, got {child_all.get('label')!r}"
    )
    assert child_all.get("mapRunArn") == map_run_arn, (
        f"expected mapRunArn {map_run_arn!r}, got {child_all.get('mapRunArn')!r}"
    )
    assert child_all.get("variableReferences") == expected_refs, (
        f"expected variableReferences {expected_refs!r} for the labeled execution, "
        f"got {child_all.get('variableReferences')!r}"
    )

    # The defect this check exists to catch: for a labeled (Map Run child) execution ARN,
    # METADATA_ONLY does not suppress the definition or variableReferences the way it does for
    # a plain execution ARN above.
    child_meta = sfn.describe_state_machine_for_execution(
        executionArn=child_arn, includedData="METADATA_ONLY"
    )
    assert child_meta.get("variableReferences") == expected_refs, (
        f"expected METADATA_ONLY on the labeled execution to still carry variableReferences "
        f"{expected_refs!r}, got {child_meta.get('variableReferences')!r}"
    )
    assert child_meta["definition"] != "{}", (
        "expected METADATA_ONLY on the labeled execution to still carry the full definition, "
        "but it collapsed to '{}'"
    )


def _stop_if_running(sfn, exec_arn):
    desc = sfn.describe_execution(executionArn=exec_arn)
    if desc["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
