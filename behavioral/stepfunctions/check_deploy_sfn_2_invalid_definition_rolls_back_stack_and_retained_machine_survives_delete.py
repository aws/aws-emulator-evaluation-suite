"""deploy-sfn-2-invalid-definition-rolls-back-stack-and-retained-machine-survives-delete."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sfn-2-invalid-definition-rolls-back-stack-and-retained-machine-survives-delete"
GROUP = "deploy-stack"
SERVICES = ["stepfunctions"]

_MISSING_STATE = "NoSuchStartState"
_BAD_DEFINITION = {
    "StartAt": _MISSING_STATE,
    "States": {"Only": {"Type": "Pass", "End": True}},
}
_GOOD_DEFINITION = {
    "StartAt": "Echo",
    "States": {
        "Echo": {
            "Type": "Pass",
            "Parameters": {"seen.$": "$.marker", "via": "retained"},
            "End": True,
        }
    },
}


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:deploy",
      "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An invalid StartAt rolls the stack back with MISSING_TRANSITION_TARGET and deletes its
    Activity; a DeletionPolicy Retain machine survives stack delete and still executes, and an
    explicit delete then makes it unresolvable.
    """
    cfn = ctx.client("cloudformation")
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")

    bad_stack = ctx.unique_name("sim2real-sfn2-rb-")
    good_stack = ctx.unique_name("sim2real-sfn2-keep-")
    bad_activity = ctx.unique_name("sim2real-sfn2-act-")
    bad_machine = ctx.unique_name("sim2real-sfn2-badsm-")
    good_machine = ctx.unique_name("sim2real-sfn2-keepsm-")

    # Both stacks are created up front and waited on in parallel: the two lifecycles are
    # independent, and serialising them doubles the wall clock for no extra evidence.
    cfn.create_stack(
        StackName=bad_stack,
        TemplateBody=_template(bad_activity, bad_machine, _BAD_DEFINITION, retain=False),
        Capabilities=["CAPABILITY_IAM"],
        OnFailure="ROLLBACK",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_safe(cfn, bad_stack))

    cfn.create_stack(
        StackName=good_stack,
        TemplateBody=_template(None, good_machine, _GOOD_DEFINITION, retain=True),
        Capabilities=["CAPABILITY_IAM"],
        OnFailure="DELETE",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack_safe(cfn, good_stack))
    # The retained resources outlive the stack, so the stack delete above cannot reach them.
    # Registered now (LIFO: runs before the stack deletes) and resolved lazily from the stack's
    # own resource list, so an abort at any later line still reaps them.
    retained: dict = {}
    ctx.on_cleanup(lambda: _delete_retained_safe(cfn, sfn, iam, good_stack, retained))

    with ThreadPoolExecutor(max_workers=2) as pool:
        bad_f = pool.submit(_wait_terminal, cfn, bad_stack)
        good_f = pool.submit(_wait_terminal, cfn, good_stack)
        bad_status, good_status = bad_f.result(), good_f.result()

    # ---- negative: invalid definition -> whole stack rolled back -------------------------
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"stack with an invalid StartAt ended {bad_status!r}, expected 'ROLLBACK_COMPLETE'"
    )
    events = _stack_events(cfn, bad_stack)
    sm_failed = [e for e in events if e["LogicalResourceId"] == "Machine"
                 and e["ResourceStatus"] == "CREATE_FAILED"]
    assert len(sm_failed) == 1, (
        f"expected exactly one CREATE_FAILED event for the StateMachine, got "
        f"{[(e['ResourceStatus'], e.get('ResourceStatusReason')) for e in events if e['LogicalResourceId'] == 'Machine']!r}"
    )
    reason = sm_failed[0].get("ResourceStatusReason") or ""
    assert "MISSING_TRANSITION_TARGET" in reason, (
        f"StateMachine CREATE_FAILED reason does not carry Step Functions' definition error: {reason!r}"
    )
    assert f"{_MISSING_STATE} at /StartAt" in reason, (
        f"StateMachine CREATE_FAILED reason does not locate the missing target "
        f"{_MISSING_STATE!r} at /StartAt: {reason!r}"
    )

    act_states = [e["ResourceStatus"] for e in reversed(events)
                  if e["LogicalResourceId"] == "Activity"]
    assert "CREATE_COMPLETE" in act_states and act_states[-1] == "DELETE_COMPLETE", (
        f"Activity should be created then deleted by the rollback; its event sequence was {act_states!r}"
    )
    act_arn = next(
        (e.get("PhysicalResourceId") for e in events
         if e["LogicalResourceId"] == "Activity" and e["ResourceStatus"] == "CREATE_COMPLETE"),
        None,
    )
    assert act_arn and act_arn.startswith("arn:") and act_arn.endswith(":activity:" + bad_activity), (
        f"Activity CREATE_COMPLETE event carried physical id {act_arn!r}, expected an ARN ending "
        f"':activity:{bad_activity}'"
    )

    act_code, act_message = _poll_until(
        lambda: _error(lambda: sfn.describe_activity(activityArn=act_arn)),
        lambda r: r[0] != _NO_ERROR, timeout_s=90.0, interval_s=3.0,
    )
    assert act_code == "ActivityDoesNotExist", (
        f"DescribeActivity on the rolled-back Activity returned {act_code!r}, expected 'ActivityDoesNotExist'"
    )
    expected = f"Activity Does Not Exist: '{act_arn}'"
    assert act_message == expected, f"expected message {expected!r}, got {act_message!r}"

    # The machine itself must never have come into being.
    bad_sm_arn = _sibling_arn(act_arn, "stateMachine", bad_machine)
    bad_sm_code, bad_sm_message = _error(lambda: sfn.describe_state_machine(stateMachineArn=bad_sm_arn))
    assert bad_sm_code == "StateMachineDoesNotExist", (
        f"DescribeStateMachine on the never-created machine {bad_sm_arn!r} returned {bad_sm_code!r}, "
        f"expected 'StateMachineDoesNotExist'"
    )
    expected = f"State Machine Does Not Exist: '{bad_sm_arn}'"
    assert bad_sm_message == expected, f"expected message {expected!r}, got {bad_sm_message!r}"

    # ---- positive control: valid definition, DeletionPolicy Retain -----------------------
    assert good_status == "CREATE_COMPLETE", (
        f"control stack with a valid definition ended {good_status!r}, expected 'CREATE_COMPLETE'"
    )
    phys = _physical_ids(cfn, good_stack)
    good_sm_arn, role_name = phys.get("Machine"), phys.get("ExecRole")
    retained.update(machine=good_sm_arn, role=role_name)
    assert good_sm_arn and good_sm_arn.endswith(":stateMachine:" + good_machine), (
        f"control stack's Machine physical id is {good_sm_arn!r}, expected ARN ending "
        f"':stateMachine:{good_machine}'"
    )

    cfn.delete_stack(StackName=good_stack)
    del_status = _wait_terminal(cfn, _STACK_IDS[good_stack])
    assert del_status == "DELETE_COMPLETE", (
        f"control stack delete ended {del_status!r}, expected 'DELETE_COMPLETE'"
    )
    good_events = _stack_events(cfn, good_stack)
    skipped = {e["LogicalResourceId"] for e in good_events if e["ResourceStatus"] == "DELETE_SKIPPED"}
    assert "Machine" in skipped, (
        f"Retain machine was not DELETE_SKIPPED by the stack delete; DELETE_SKIPPED ids were {sorted(skipped)!r}"
    )

    desc = sfn.describe_state_machine(stateMachineArn=good_sm_arn)
    assert desc["status"] == "ACTIVE", (
        f"retained machine status after stack delete is {desc['status']!r}, expected 'ACTIVE'"
    )

    marker = ctx.unique_name("m-")
    ex_arn = sfn.start_execution(
        stateMachineArn=good_sm_arn, input=json.dumps({"marker": marker})
    )["executionArn"]
    ex = _poll_until(
        lambda: sfn.describe_execution(executionArn=ex_arn),
        lambda d: d["status"] != "RUNNING", timeout_s=90.0, interval_s=2.0,
    )
    assert ex["status"] == "SUCCEEDED", (
        f"execution on the retained machine ended {ex['status']!r} "
        f"(error={ex.get('error')!r}, cause={ex.get('cause')!r}), expected 'SUCCEEDED'"
    )
    out = json.loads(ex["output"])
    assert out == {"seen": marker, "via": "retained"}, (
        f"retained machine produced {out!r}, expected {{'seen': {marker!r}, 'via': 'retained'}}"
    )

    # ---- explicit delete of the retained machine makes it unresolvable -------------------
    # Deletion is asynchronous and its latency varies widely, so the ceiling is generous. While
    # the machine still resolves it must already report DELETING -- never ACTIVE again.
    sfn.delete_state_machine(stateMachineArn=good_sm_arn)
    seen_while_resolvable = set()

    def _probe_deleted():
        try:
            seen_while_resolvable.add(
                sfn.describe_state_machine(stateMachineArn=good_sm_arn)["status"])
            return _NO_ERROR, None
        except ClientError as e:
            return e.response["Error"]["Code"], e.response["Error"].get("Message")

    gone, gone_message = _poll_until(
        _probe_deleted, lambda r: r[0] != _NO_ERROR, timeout_s=300.0, interval_s=5.0)
    assert seen_while_resolvable <= {"DELETING"}, (
        f"after DeleteStateMachine the machine still reported {sorted(seen_while_resolvable)!r}; "
        f"the only legal status while it resolves is 'DELETING'"
    )
    assert gone == "StateMachineDoesNotExist", (
        f"DescribeStateMachine after explicit delete returned {gone!r}, expected 'StateMachineDoesNotExist'"
    )
    expected = f"State Machine Does Not Exist: '{good_sm_arn}'"
    assert gone_message == expected, f"expected message {expected!r}, got {gone_message!r}"



_NO_ERROR = "<call succeeded>"
_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED",
}


def _error(fn):
    """The AWS error (code, message), or a sentinel code that can never be mistaken for one on
    success."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    return _NO_ERROR, None


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _wait_terminal(cfn, stack_ref, timeout_s=600.0):
    """Poll a stack to a terminal status. Pass the stack ID once a delete is in flight: a
    deleted stack is describable by ID but not by name."""
    return _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_ref)["Stacks"][0]["StackStatus"],
        lambda st: st in _TERMINAL, timeout_s=timeout_s, interval_s=5.0,
    )


def _stack_id(cfn, stack_name):
    return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackId"]


def _stack_events(cfn, stack_name):
    """All events, newest first. Uses the stack id when known so a deleted stack stays readable."""
    ref = _STACK_IDS.get(stack_name) or stack_name
    out = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=ref):
        out.extend(page["StackEvents"])
    return out


_STACK_IDS: dict = {}


def _physical_ids(cfn, stack_name):
    _STACK_IDS[stack_name] = _stack_id(cfn, stack_name)
    out = {}
    for page in cfn.get_paginator("list_stack_resources").paginate(StackName=stack_name):
        for r in page["StackResourceSummaries"]:
            out[r["LogicalResourceId"]] = r.get("PhysicalResourceId")
    return out


def _sibling_arn(arn, resource_type, name):
    """Same partition/region/account as `arn`, different states resource."""
    parts = arn.split(":", 6)
    assert len(parts) >= 6 and parts[0] == "arn" and parts[2] == "states", f"not a states ARN: {arn!r}"
    return ":".join(parts[:5] + [resource_type, name])


def _template(activity_name, machine_name, definition, retain):
    resources = {
        "ExecRole": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "AssumeRolePolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Principal": {"Service": "states.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }],
                },
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            },
        },
        "Machine": {
            "Type": "AWS::StepFunctions::StateMachine",
            "Properties": {
                "StateMachineName": machine_name,
                "RoleArn": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                "DefinitionString": json.dumps(definition),
                "Tags": [{"Key": "sim2real", "Value": CHECK}],
            },
        },
    }
    if activity_name is not None:
        resources["Activity"] = {
            "Type": "AWS::StepFunctions::Activity",
            "Properties": {"Name": activity_name, "Tags": [{"Key": "sim2real", "Value": CHECK}]},
        }
        resources["Machine"]["DependsOn"] = "Activity"
    if retain:
        for logical in ("Machine", "ExecRole"):
            resources[logical]["DeletionPolicy"] = "Retain"
            resources[logical]["UpdateReplacePolicy"] = "Retain"
    return json.dumps({"AWSTemplateFormatVersion": "2010-09-09", "Resources": resources})


def _delete_stack_safe(cfn, stack_name):
    try:
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )
    except Exception as e:  # noqa: BLE001 - re-raised
        raise RuntimeError(f"stack {stack_name}: {e}") from e


def _delete_retained_safe(cfn, sfn, iam, stack_name, retained):
    machine, role = retained.get("machine"), retained.get("role")
    if not (machine and role):
        # Aborted before the ids were read: recover them from the stack if it still exists.
        try:
            phys = _physical_ids(cfn, stack_name)
            machine, role = machine or phys.get("Machine"), role or phys.get("ExecRole")
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
            ):
                raise
    # The role delete runs even when the machine delete raises; either failure propagates.
    try:
        if machine:
            try:
                sfn.delete_state_machine(stateMachineArn=machine)
            except ClientError as e:
                if e.response["Error"]["Code"] != "StateMachineDoesNotExist":
                    raise
    finally:
        if role:
            try:
                iam.delete_role(RoleName=role)
            except ClientError as e:
                if e.response["Error"]["Code"] != "NoSuchEntity":
                    raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
