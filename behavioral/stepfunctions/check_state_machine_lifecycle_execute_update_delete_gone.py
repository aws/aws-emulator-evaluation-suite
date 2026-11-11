"""state-machine-lifecycle-execute-update-delete-gone."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "state-machine-lifecycle-execute-update-delete-gone"
GROUP = 'state_machine_lifecycle'
SERVICES = ['stepfunctions']

_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _definition(version):
    return {
        "Comment": "behavioral lifecycle: echo the input under a versioned constant",
        "StartAt": "P",
        "States": {
            "P": {"Type": "Pass", "Parameters": {"v": version, "echo.$": "$.in"}, "End": True}
        },
    }


def _create_sfn_role(ctx):
    """An execution role Step Functions may assume, deleted at cleanup."""
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
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _create_sm_retrying(sfn, **kwargs):
    """CreateStateMachine, retried while a just-created role is still propagating in IAM."""
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return sfn.create_state_machine(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)


def _delete_if_present(sfn, arn):
    """Teardown: delete the state machine unless the check already proved it gone."""
    try:
        sfn.delete_state_machine(stateMachineArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
            raise


def _wait_terminal(sfn, exec_arn, *, timeout_s=120):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] in _TERMINAL:
            return last
        time.sleep(0.5)
    raise AssertionError(f"execution not terminal within {timeout_s}s: {last!r}")


def _run(sfn, sm_arn, payload):
    exec_arn = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps(payload))["executionArn"]
    desc = _wait_terminal(sfn, exec_arn)
    assert desc["status"] == "SUCCEEDED", (
        f"execution: expected SUCCEEDED, got {desc['status']}: {desc.get('error')} {desc.get('cause')}"
    )
    return exec_arn, json.loads(desc["output"])


def _error(fn):
    """The (code, HTTP status, message) `fn` is refused with; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected the call on a deleted state machine to fail, it returned {result!r}")


def _poll_refusal(fn, *, timeout_s=180, interval_s=2.0):
    """Call fn() until it is refused; a describe that still answers mid-deletion is transient."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            last = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            return err.get("Code"), status, err.get("Message") or ""
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"DescribeStateMachine still answered {timeout_s}s after the delete: "
                f"status {last.get('status')!r}"
            )
        time.sleep(interval_s)


def _list_all(list_fn, field, **kwargs):
    items, token = [], None
    while True:
        call = dict(kwargs)
        if token:
            call["nextToken"] = token
        page = list_fn(**call)
        items.extend(page[field])
        token = page.get("nextToken")
        if not token:
            return items


def _partition(ctx) -> str:
    """The caller's partition, taken from its own ARN — never a literal 'aws'."""
    arn = ctx.client("sts").get_caller_identity()["Arn"]
    parts = arn.split(":")
    assert len(parts) > 2 and parts[0] == "arn" and parts[1], (
        f"GetCallerIdentity returned Arn {arn!r}, from which no partition can be read"
    )
    return parts[1]


@tags("axis:happy-path", "cap:c3", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A state machine runs, an update changes what the next execution computes, and once deleted
    it is gone: not describable, not listed, and cannot be started."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    name = ctx.unique_name("sim2real-behav-sm-")
    sm_arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(_definition(1)),
        roleArn=role_arn,
        type="STANDARD",
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: _delete_if_present(sfn, sm_arn))

    expected_arn = f"arn:{_partition(ctx)}:states:{ctx.region}:{ctx.account}:stateMachine:{name}"
    assert sm_arn == expected_arn, f"state machine ARN: expected {expected_arn!r}, got {sm_arn!r}"

    desc = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert desc["status"] == "ACTIVE", f"DescribeStateMachine status: expected ACTIVE, got {desc['status']!r}"
    assert desc["stateMachineArn"] == sm_arn, (
        f"DescribeStateMachine ARN: expected {sm_arn!r}, got {desc['stateMachineArn']!r}"
    )
    assert desc["roleArn"] == role_arn, f"roleArn: expected {role_arn!r}, got {desc['roleArn']!r}"
    rev1 = desc.get("revisionId")

    first_arn, out1 = _run(sfn, sm_arn, {"in": "x"})
    assert out1 == {"v": 1, "echo": "x"}, f"first execution output: expected {{'v': 1, 'echo': 'x'}}, got {out1!r}"

    sfn.update_state_machine(stateMachineArn=sm_arn, definition=json.dumps(_definition(2)))
    desc2 = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert desc2.get("revisionId") and desc2.get("revisionId") != rev1, (
        f"DescribeStateMachine revisionId must change on update: before {rev1!r}, after "
        f"{desc2.get('revisionId')!r}"
    )
    stored = json.loads(desc2["definition"])
    assert stored["States"]["P"]["Parameters"]["v"] == 2, (
        f"DescribeStateMachine definition after update: expected v=2, got {stored!r}"
    )

    # UpdateStateMachine is eventually consistent for StartExecution (AWS documents that an
    # execution started right after the update may still use the previous definition).
    started = [first_arn]
    deadline = time.monotonic() + 60.0
    while True:
        exec_arn, out = _run(sfn, sm_arn, {"in": "y"})
        started.append(exec_arn)
        assert out in ({"v": 1, "echo": "y"}, {"v": 2, "echo": "y"}), (
            f"execution after update: expected v 1 or 2 with echo 'y', got {out!r}"
        )
        if out["v"] == 2:
            break
        assert time.monotonic() < deadline, "executions still ran the previous definition 60s after the update"
        time.sleep(2)

    listed = {e["executionArn"] for e in _list_all(sfn.list_executions, "executions", stateMachineArn=sm_arn)}
    missing = [a for a in started if a not in listed]
    assert not missing, f"ListExecutions is missing {len(missing)} of {len(started)} started executions"

    sfn.delete_state_machine(stateMachineArn=sm_arn)

    # Gone beat 1: the by-id read reaches the terminal not-found answer (DELETING is never required).
    gone = f"State Machine Does Not Exist: '{sm_arn}'"
    code, status, message = _poll_refusal(lambda: sfn.describe_state_machine(stateMachineArn=sm_arn))
    assert (code, message) == ("StateMachineDoesNotExist", gone) and isinstance(status, int) and 400 <= status < 500, (
        f"DescribeStateMachine after delete: expected StateMachineDoesNotExist/4xx {gone!r}, "
        f"got {code!r}/{status!r}: {message!r}"
    )

    # Gone beat 2: the listing no longer holds it.
    arns = {m["stateMachineArn"] for m in _list_all(sfn.list_state_machines, "stateMachines")}
    assert sm_arn not in arns, "ListStateMachines still lists the deleted state machine"

    # Gone beat 3: the dead ARN cannot be started.
    code, status, message = _error(lambda: sfn.start_execution(stateMachineArn=sm_arn, input="{}"))
    assert (code, message) == ("StateMachineDoesNotExist", gone) and isinstance(status, int) and 400 <= status < 500, (
        f"StartExecution on the deleted state machine: expected StateMachineDoesNotExist/4xx {gone!r}, "
        f"got {code!r}/{status!r}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
