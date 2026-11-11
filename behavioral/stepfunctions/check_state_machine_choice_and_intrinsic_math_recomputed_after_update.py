"""state-machine-choice-and-intrinsic-math-recomputed-after-update."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "state-machine-choice-and-intrinsic-math-recomputed-after-update"
GROUP = 'state_machine_lifecycle'
SERVICES = ['stepfunctions']

_TERMINAL = ("SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED")


def _definition(threshold, step):
    """Inputs at or above ``threshold`` add ``step``; inputs below it subtract ``step``."""
    return {
        "StartAt": "Route",
        "States": {
            "Route": {
                "Type": "Choice",
                "Choices": [{"Variable": "$.n", "NumericGreaterThanEquals": threshold, "Next": "High"}],
                "Default": "Low",
            },
            "High": {"Type": "Pass", "Parameters": {"branch": "high", "out.$": f"States.MathAdd($.n, {step})"},
                     "End": True},
            "Low": {"Type": "Pass", "Parameters": {"branch": "low", "out.$": f"States.MathAdd($.n, {-step})"},
                    "End": True},
        },
    }


def _expect(threshold, step, n):
    return {"branch": "high", "out": n + step} if n >= threshold else {"branch": "low", "out": n - step}


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
    deadline = time.monotonic() + 40.0
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


def _wait_terminal(sfn, exec_arn, *, timeout_s=40):
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
    """Call fn() until it is refused; a describe that still answers mid-deletion is transient.

    AWS can keep a deleted STANDARD machine DELETING for over two minutes, so this one wait gets 180 s."""
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
    """A Choice state routes random inputs by a threshold and an intrinsic MathAdd computes each
    output; an update moving the threshold and step changes both the branch and the arithmetic of the
    next executions, and once deleted the machine is gone and cannot be started."""
    rng = random.SystemRandom()
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    name = ctx.unique_name("sim2real-behav-sm-choice-")
    t1, s1 = rng.randint(100, 200), rng.randint(2, 50)
    t2, s2 = rng.randint(300, 400), rng.randint(51, 99)
    # One input under both thresholds, one between them (high before the update, low after), one above both.
    inputs = [rng.randint(0, 99), rng.randint(201, 299), rng.randint(401, 999)]
    sm_arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(_definition(t1, s1)),
        roleArn=role_arn,
        type="STANDARD",
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: _delete_if_present(sfn, sm_arn))
    expected_arn = f"arn:{_partition(ctx)}:states:{ctx.region}:{ctx.account}:stateMachine:{name}"
    assert sm_arn == expected_arn, f"state machine ARN: expected {expected_arn!r}, got {sm_arn!r}"

    started = []
    for n in inputs:
        exec_arn, out = _run(sfn, sm_arn, {"n": n})
        started.append(exec_arn)
        assert out == _expect(t1, s1, n), f"input {n} before the update: expected {_expect(t1, s1, n)!r}, got {out!r}"
    rev1 = sfn.describe_state_machine(stateMachineArn=sm_arn).get("revisionId")

    sfn.update_state_machine(stateMachineArn=sm_arn, definition=json.dumps(_definition(t2, s2)))
    desc = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert desc.get("revisionId") and desc["revisionId"] != rev1, (
        f"revisionId must change on update: before {rev1!r}, after {desc.get('revisionId')!r}"
    )
    stored = json.loads(desc["definition"])
    assert stored == _definition(t2, s2), f"DescribeStateMachine definition after update: got {stored!r}"

    # UpdateStateMachine is eventually consistent for StartExecution: an execution started after
    # it may still run the previous definition, so each input is retried until the new one answers.
    deadline = time.monotonic() + 40.0
    for n in (inputs[1], inputs[0], inputs[2]):
        while True:
            exec_arn, out = _run(sfn, sm_arn, {"n": n})
            started.append(exec_arn)
            assert out in (_expect(t1, s1, n), _expect(t2, s2, n)), (
                f"input {n} after the update: expected {_expect(t2, s2, n)!r} (or the previous "
                f"{_expect(t1, s1, n)!r} while the update propagates), got {out!r}"
            )
            if out == _expect(t2, s2, n):
                break
            assert time.monotonic() < deadline, (
                f"executions still ran the previous definition 40s after the update; last output {out!r}"
            )
            time.sleep(2)

    listed = {e["executionArn"] for e in _list_all(sfn.list_executions, "executions", stateMachineArn=sm_arn)}
    missing = [a for a in started if a not in listed]
    assert not missing, f"ListExecutions is missing {len(missing)} of {len(started)} started executions"

    sfn.delete_state_machine(stateMachineArn=sm_arn)
    gone = f"State Machine Does Not Exist: '{sm_arn}'"
    code, status, message = _poll_refusal(lambda: sfn.describe_state_machine(stateMachineArn=sm_arn))
    assert (code, message) == ("StateMachineDoesNotExist", gone) and status == 400, (
        f"DescribeStateMachine after delete: expected StateMachineDoesNotExist/400 {gone!r}, "
        f"got {code!r}/{status!r}: {message!r}"
    )
    arns = {m["stateMachineArn"] for m in _list_all(sfn.list_state_machines, "stateMachines")}
    assert sm_arn not in arns, "ListStateMachines still lists the deleted state machine"
    code, status, message = _error(lambda: sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({"n": 1})))
    assert (code, message) == ("StateMachineDoesNotExist", gone) and status == 400, (
        f"StartExecution on the deleted state machine: expected StateMachineDoesNotExist/400 {gone!r}, "
        f"got {code!r}/{status!r}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
