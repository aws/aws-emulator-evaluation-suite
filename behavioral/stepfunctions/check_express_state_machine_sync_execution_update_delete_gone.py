"""express-state-machine-sync-execution-update-delete-gone."""
from __future__ import annotations

import json
import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "express-state-machine-sync-execution-update-delete-gone"
GROUP = 'state_machine_lifecycle'
SERVICES = ['stepfunctions']


def _definition(label):
    """Joins the input's two words around ``label`` with States.Format."""
    return {
        "StartAt": "Join",
        "States": {
            "Join": {"Type": "Pass",
                     "Parameters": {"joined.$": f"States.Format('{{}}/{label}/{{}}', $.a, $.b)"},
                     "End": True},
        },
    }


def _sync(sfn, sm_arn, payload):
    """StartSyncExecution; the call itself returns the terminal result."""
    resp = sfn.start_sync_execution(stateMachineArn=sm_arn, input=json.dumps(payload))
    assert resp["status"] == "SUCCEEDED", (
        f"sync execution: expected SUCCEEDED, got {resp['status']}: {resp.get('error')} {resp.get('cause')}"
    )
    assert json.loads(resp["input"]) == payload, f"sync execution echoed input {resp['input']!r}, sent {payload!r}"
    return json.loads(resp["output"])


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




def _error(fn):
    """The (code, HTTP status, message) `fn` is refused with; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected the call on a deleted state machine to fail, it returned {result!r}")


def _poll_refusal(fn, *, timeout_s=120, interval_s=2.0):
    """Call fn() until it is refused; a describe that still answers mid-deletion is transient.

    AWS keeps a deleted state machine DELETING for longer than 40 s, so this one wait gets 120 s."""
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
    """An EXPRESS state machine answers StartSyncExecution with output computed from random input;
    an update changes what the next sync execution computes, and once deleted the machine is not
    describable, not listed and refuses StartSyncExecution."""
    rng = random.SystemRandom()
    sfn = ctx.client("stepfunctions")
    role_arn = _create_sfn_role(ctx)
    name = ctx.unique_name("sim2real-behav-sm-express-")
    v1 = f"one{rng.randrange(10**6):06d}"
    v2 = f"two{rng.randrange(10**6):06d}"
    sm_arn = _create_sm_retrying(
        sfn,
        name=name,
        definition=json.dumps(_definition(v1)),
        roleArn=role_arn,
        type="EXPRESS",
        tags=[{"key": "sim2real-check", "value": CHECK}],
    )["stateMachineArn"]
    ctx.on_cleanup(lambda: _delete_if_present(sfn, sm_arn))
    expected_arn = f"arn:{_partition(ctx)}:states:{ctx.region}:{ctx.account}:stateMachine:{name}"
    assert sm_arn == expected_arn, f"state machine ARN: expected {expected_arn!r}, got {sm_arn!r}"
    desc = sfn.describe_state_machine(stateMachineArn=sm_arn)
    assert (desc["status"], desc["type"]) == ("ACTIVE", "EXPRESS"), (
        f"DescribeStateMachine: expected ACTIVE/EXPRESS, got {desc['status']!r}/{desc['type']!r}"
    )

    a, b = f"a{rng.randrange(10**6)}", f"b{rng.randrange(10**6)}"
    out = _sync(sfn, sm_arn, {"a": a, "b": b})
    assert out == {"joined": f"{a}/{v1}/{b}"}, f"first sync execution: expected {a}/{v1}/{b}, got {out!r}"

    sfn.update_state_machine(stateMachineArn=sm_arn, definition=json.dumps(_definition(v2)))
    stored = json.loads(sfn.describe_state_machine(stateMachineArn=sm_arn)["definition"])
    assert stored == _definition(v2), f"DescribeStateMachine definition after update: got {stored!r}"

    # An execution started right after UpdateStateMachine may still run the previous definition.
    deadline = time.monotonic() + 40.0
    while True:
        out = _sync(sfn, sm_arn, {"a": b, "b": a})
        assert out in ({"joined": f"{b}/{v1}/{a}"}, {"joined": f"{b}/{v2}/{a}"}), (
            f"sync execution after update: expected {b}/<label>/{a} with the old or new label, got {out!r}"
        )
        if out == {"joined": f"{b}/{v2}/{a}"}:
            break
        assert time.monotonic() < deadline, (
            f"sync executions still ran the previous definition 40s after the update; last output {out!r}"
        )
        time.sleep(2)

    sfn.delete_state_machine(stateMachineArn=sm_arn)
    gone = f"State Machine Does Not Exist: '{sm_arn}'"
    code, status, message = _poll_refusal(lambda: sfn.describe_state_machine(stateMachineArn=sm_arn))
    assert (code, message) == ("StateMachineDoesNotExist", gone) and status == 400, (
        f"DescribeStateMachine after delete: expected StateMachineDoesNotExist/400 {gone!r}, "
        f"got {code!r}/{status!r}: {message!r}"
    )
    arns = {m["stateMachineArn"] for m in _list_all(sfn.list_state_machines, "stateMachines")}
    assert sm_arn not in arns, "ListStateMachines still lists the deleted state machine"
    code, status, message = _error(
        lambda: sfn.start_sync_execution(stateMachineArn=sm_arn, input=json.dumps({"a": a, "b": b})))
    assert (code, message) == ("StateMachineDoesNotExist", gone) and status == 400, (
        f"StartSyncExecution on the deleted state machine: expected StateMachineDoesNotExist/400 {gone!r}, "
        f"got {code!r}/{status!r}: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
