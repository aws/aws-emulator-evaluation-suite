"""cloudcontrol-state-machine-definition-object-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-state-machine-definition-object-round-trip"
GROUP = "deploy"
SERVICES = ["cloudcontrol", "iam", "stepfunctions"]

_TYPE = "AWS::StepFunctions::StateMachine"
_DEF_V1 = {"Comment": "sim2real v1", "StartAt": "P",
           "States": {"P": {"Type": "Pass", "Result": {"version": 1, "via": "cloudcontrol"}, "End": True}}}
_DEF_V2 = {"Comment": "sim2real v2", "StartAt": "Q",
           "States": {"Q": {"Type": "Pass", "Result": {"version": 2, "via": "cloudcontrol"}, "End": True}}}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane",
      "concern:representation", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A Definition object sent through Cloud Control is the state machine Step Functions runs: the
    identifier is its ARN, the write-only Definition reads back as an equivalent DefinitionString,
    an `add` patch of /Definition changes what an execution outputs, and a delete removes it."""
    ctx.verify_account_safety()
    cloudcontrol = ctx.client("cloudcontrol")
    iam = ctx.client("iam")
    sfn = ctx.client("stepfunctions")
    role_arn = _states_role(ctx, iam)
    name = ctx.unique_name("sim2real-xsvc-ccsm-")
    expected_arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{name}"

    created = _create_state_machine(ctx, cloudcontrol, sfn, {
        "StateMachineName": name, "RoleArn": role_arn, "Definition": _DEF_V1,
        "StateMachineType": "STANDARD"})
    assert created["OperationStatus"] == "SUCCESS", (
        f"create ended {created['OperationStatus']!r}: {created.get('ErrorCode')!r}"
    )
    identifier = created["Identifier"]
    assert identifier == expected_arn, (
        f"the primary identifier is not the state machine ARN for the created name "
        f"(ends with the name: {identifier.endswith(name)!r})"
    )

    native = sfn.describe_state_machine(stateMachineArn=identifier)
    assert native["name"] == name and native["roleArn"] == role_arn, (
        f"Step Functions resolves the identifier to {native['name']!r} with a different role"
    )
    assert json.loads(native["definition"]) == _DEF_V1, (
        f"the native definition {native['definition']!r} is not the Definition object sent"
    )
    props = json.loads(cloudcontrol.get_resource(
        TypeName=_TYPE, Identifier=identifier)["ResourceDescription"]["Properties"])
    assert "Definition" not in props, f"write-only Definition was read back: {sorted(props)!r}"
    assert json.loads(props["DefinitionString"]) == _DEF_V1, (
        f"GetResource DefinitionString {props['DefinitionString']!r} is not the Definition sent"
    )
    assert props.get("Arn") == identifier and props.get("RoleArn") == role_arn, (
        f"GetResource Arn/RoleArn disagree with the native machine: keys {sorted(props)!r}"
    )

    updated = _cc_wait(cloudcontrol, cloudcontrol.update_resource(
        TypeName=_TYPE, Identifier=identifier,
        PatchDocument=json.dumps([{"op": "add", "path": "/Definition", "value": _DEF_V2}])),
        description="cloudcontrol update Definition")
    assert updated["OperationStatus"] == "SUCCESS", (
        f"update ended {updated['OperationStatus']!r}: {updated.get('StatusMessage')!r}"
    )
    native = sfn.describe_state_machine(stateMachineArn=identifier)
    assert json.loads(native["definition"]) == _DEF_V2, (
        f"after the patch the native definition is {native['definition']!r}"
    )
    props = json.loads(cloudcontrol.get_resource(
        TypeName=_TYPE, Identifier=identifier)["ResourceDescription"]["Properties"])
    assert json.loads(props["DefinitionString"]) == _DEF_V2, (
        f"GetResource after the patch reports {props['DefinitionString']!r}"
    )

    execution = sfn.start_execution(stateMachineArn=identifier, input="{}")["executionArn"]
    done = _poll_until(lambda: sfn.describe_execution(executionArn=execution),
                       lambda d: d["status"] != "RUNNING", timeout_s=120.0,
                       description="the execution leaves RUNNING")
    assert done["status"] == "SUCCEEDED", f"the execution ended {done['status']!r}"
    assert json.loads(done["output"]) == _DEF_V2["States"]["Q"]["Result"], (
        f"the execution output {done['output']!r} is not the patched definition's result"
    )

    deleted = _cc_wait(cloudcontrol, cloudcontrol.delete_resource(TypeName=_TYPE, Identifier=identifier),
                       description="cloudcontrol delete")
    assert deleted["OperationStatus"] == "SUCCESS", (
        f"delete ended {deleted['OperationStatus']!r}: {deleted.get('StatusMessage')!r}"
    )
    code, message = _error(lambda: sfn.describe_state_machine(stateMachineArn=identifier))
    assert code == "StateMachineDoesNotExist", f"DescribeStateMachine after delete gave {code!r}"
    assert message == f"State Machine Does Not Exist: '{expected_arn}'", (
        f"DescribeStateMachine not-found message was {message!r}"
    )


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn) -> tuple[str, str]:
    """``(code, message)`` that ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=3.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _cc_wait(cloudcontrol, response: dict, *, description: str, timeout_s=300.0) -> dict:
    """Poll a Cloud Control ProgressEvent to a terminal OperationStatus and return it."""
    event = response["ProgressEvent"]
    token = event["RequestToken"]
    terminal = {"SUCCESS", "FAILED", "CANCEL_COMPLETE"}
    if event.get("OperationStatus") in terminal:
        return event
    return _poll_until(
        lambda: cloudcontrol.get_resource_request_status(RequestToken=token)["ProgressEvent"],
        lambda e: e.get("OperationStatus") in terminal,
        timeout_s=timeout_s, interval_s=3.0, description=description,
    )


_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                   "Action": "sts:AssumeRole"}],
}
_ROLE_NOT_ASSUMABLE = "is not authorized to assume the provided role"


def _states_role(ctx, iam) -> str:
    """A role Step Functions may assume, created by this check and deleted after it."""
    name = ctx.unique_name("sim2real-xsvc-ccsfn-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST),
                          Description="sim2real cloudcontrol state machine role")["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    return arn


def _create_state_machine(ctx, cloudcontrol, sfn, desired: dict) -> dict:
    """Create AWS::StepFunctions::StateMachine through Cloud Control and return the event.

    IAM propagation exposes no condition to poll, so a create refused because the fresh role is
    not yet assumable is retried, bounded; every other outcome is returned to the caller.
    """
    arn = f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{desired['StateMachineName']}"
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn),
                             "StateMachineDoesNotExist"))
    deadline = time.monotonic() + 120
    while True:
        event = _cc_wait(cloudcontrol, cloudcontrol.create_resource(
            TypeName="AWS::StepFunctions::StateMachine", DesiredState=json.dumps(desired)),
            description=f"cloudcontrol create {desired['StateMachineName']}")
        if (event["OperationStatus"] == "FAILED"
                and _ROLE_NOT_ASSUMABLE in (event.get("StatusMessage") or "")
                and time.monotonic() < deadline):
            time.sleep(2)
            continue
        return event


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
