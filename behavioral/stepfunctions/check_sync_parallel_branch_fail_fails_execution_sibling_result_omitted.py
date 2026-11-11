"""sync-parallel-branch-fail-fails-execution-sibling-result-omitted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sync-parallel-branch-fail-fails-execution-sibling-result-omitted"
GROUP = "express_workflows"
SERVICES = ["stepfunctions"]

_FAIL_ERROR = "ParallelBranchBoom"
_FAIL_CAUSE = "branch A deliberately fails while branch B succeeds"
_SIBLING_RESULT = {"branch": "B", "ok": True}


def _trust_policy() -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )


def _definition() -> str:
    return json.dumps(
        {
            "Comment": "a Parallel state whose branch A fails while branch B succeeds",
            "StartAt": "Fan",
            "States": {
                "Fan": {
                    "Type": "Parallel",
                    "End": True,
                    "Branches": [
                        {
                            "StartAt": "BranchA",
                            "States": {
                                "BranchA": {
                                    "Type": "Fail",
                                    "Error": _FAIL_ERROR,
                                    "Cause": _FAIL_CAUSE,
                                }
                            },
                        },
                        {
                            "StartAt": "BranchB",
                            "States": {
                                "BranchB": {
                                    "Type": "Pass",
                                    "Result": _SIBLING_RESULT,
                                    "End": True,
                                }
                            },
                        },
                    ],
                }
            },
        }
    )


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnpar-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust_policy(),
        Path="/sim2real/",
        Description="Step Functions execution role",
        Tags=[{"Key": "sim2real", "Value": "1"}, {"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _create_state_machine(ctx, role_arn: str) -> str:
    """An EXPRESS state machine, retrying only the AccessDeniedException raised while the
    freshly created role's assume-role grant propagates, polling every 2s against a deadline."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-sfnpar-")
    deadline = time.monotonic() + 120.0
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name,
                definition=_definition(),
                roleArn=role_arn,
                type="EXPRESS",
                tags=[
                    {"key": "sim2real", "value": "1"},
                    {"key": "sim2real-check", "value": CHECK},
                ],
            )["stateMachineArn"]
            ctx.on_cleanup(lambda a=arn: sfn.delete_state_machine(stateMachineArn=a))
            return arn
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(2.0)
    raise AssertionError(
        f"CreateStateMachine(type=EXPRESS) still AccessDenied 120s after the role was "
        f"created. Last error: {last}"
    )


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A synchronous Express execution of a Parallel state whose branch A fails ends
    FAILED with branch A's Error and Cause, and branch B's successful result never
    surfaces: a FAILED sync response carries no output field at all."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    sm_arn = _create_state_machine(ctx, role_arn)

    try:
        boom = sfn.start_sync_execution(stateMachineArn=sm_arn, input=json.dumps({}))
    except ClientError as exc:
        err = exc.response.get("Error", {})
        raise AssertionError(
            "StartSyncExecution must report a Parallel-branch failure inside a successful "
            f"response carrying status=FAILED; it raised {err.get('Code')!r} instead "
            f"({err.get('Message')!r})."
        ) from exc

    assert boom["status"] == "FAILED", (
        f"a Parallel state with one failing branch must report status FAILED; got "
        f"{boom['status']!r}"
    )
    assert boom.get("error") == _FAIL_ERROR, (
        f"the sync response must carry the failing branch's Error verbatim; expected "
        f"{_FAIL_ERROR!r}, got {boom.get('error')!r}"
    )
    assert boom.get("cause") == _FAIL_CAUSE, (
        f"the sync response must carry the failing branch's Cause verbatim; expected "
        f"{_FAIL_CAUSE!r}, got {boom.get('cause')!r}"
    )
    assert "output" not in boom, (
        f"a FAILED synchronous Express execution must omit output entirely, so the "
        f"succeeding sibling branch's result {_SIBLING_RESULT!r} cannot leak through; it "
        f"carried output={boom.get('output')!r}"
    )

    # --- Positive control: the same machine with branch A fixed so both branches succeed
    ok_definition = json.loads(_definition())
    ok_definition["States"]["Fan"]["Branches"][0]["States"]["BranchA"] = {
        "Type": "Pass",
        "Result": {"branch": "A", "ok": True},
        "End": True,
    }
    ok_name = ctx.unique_name("sim2real-behav-sfnpar-ok-")
    ok_arn = sfn.create_state_machine(
        name=ok_name,
        definition=json.dumps(ok_definition),
        roleArn=role_arn,
        type="EXPRESS",
        tags=[{"key": "sim2real", "value": "1"}, {"key": "sim2real-check", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=ok_arn))
    ok = sfn.start_sync_execution(stateMachineArn=ok_arn, input=json.dumps({}))
    assert ok["status"] == "SUCCEEDED", (
        "with both branches fixed to succeed, the same shape must report SUCCEEDED — "
        "without this control the failure above cannot be told apart from a sync endpoint "
        f"that answers FAILED to everything; got {ok['status']!r} error={ok.get('error')!r}"
    )
    ok_output = json.loads(ok["output"])
    assert ok_output == [{"branch": "A", "ok": True}, _SIBLING_RESULT], (
        f"expected both branch results in branch order, got {ok_output!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
