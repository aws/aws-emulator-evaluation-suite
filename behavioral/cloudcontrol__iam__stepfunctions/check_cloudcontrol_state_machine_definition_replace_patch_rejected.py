"""cloudcontrol-state-machine-definition-replace-patch-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cloudcontrol-state-machine-definition-replace-patch-rejected"
GROUP = "validation"
SERVICES = ["cloudcontrol", "iam", "stepfunctions"]

_TYPE = "AWS::StepFunctions::StateMachine"
_DEF_V1 = {"StartAt": "P", "States": {"P": {"Type": "Pass", "Result": {"version": 1}, "End": True}}}
_DEF_V2 = {"StartAt": "Q", "States": {"Q": {"Type": "Pass", "Result": {"version": 2}, "End": True}}}


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A `replace` patch of the write-only /Definition is refused with ValidationException and the
    exact writeOnlyProperties message and leaves the machine's native definition and revision
    untouched, while the same change sent as `add` lands."""
    ctx.verify_account_safety()
    cloudcontrol = ctx.client("cloudcontrol")
    iam = ctx.client("iam")
    sfn = ctx.client("stepfunctions")
    role_arn = _states_role(ctx, iam)
    name = ctx.unique_name("sim2real-xsvc-ccsm-")

    created = _create_state_machine(ctx, cloudcontrol, sfn, {
        "StateMachineName": name, "RoleArn": role_arn, "Definition": _DEF_V1})
    assert created["OperationStatus"] == "SUCCESS", (
        f"create ended {created['OperationStatus']!r}: {created.get('ErrorCode')!r}"
    )
    identifier = created["Identifier"]
    before = sfn.describe_state_machine(stateMachineArn=identifier)
    assert json.loads(before["definition"]) == _DEF_V1, f"native definition {before['definition']!r}"

    code, message = _error(lambda: cloudcontrol.update_resource(
        TypeName=_TYPE, Identifier=identifier,
        PatchDocument=json.dumps([{"op": "replace", "path": "/Definition", "value": _DEF_V2}])))
    assert code == "ValidationException", f"a replace of write-only /Definition gave {code!r} ({message!r})"
    assert message == ("Invalid patch update: writeOnlyProperties [/Definition] can only be "
                       "updated using 'add' operation"), f"the refusal message was {message!r}"

    after = sfn.describe_state_machine(stateMachineArn=identifier)
    assert json.loads(after["definition"]) == _DEF_V1, (
        f"the refused patch changed the native definition to {after['definition']!r}"
    )
    assert after.get("revisionId") == before.get("revisionId"), (
        "the refused patch advanced the native revision"
    )

    updated = _cc_wait(cloudcontrol, cloudcontrol.update_resource(
        TypeName=_TYPE, Identifier=identifier,
        PatchDocument=json.dumps([{"op": "add", "path": "/Definition", "value": _DEF_V2}])),
        description="cloudcontrol add-patch Definition")
    assert updated["OperationStatus"] == "SUCCESS", (
        f"the positive control add-patch ended {updated['OperationStatus']!r}: {updated.get('StatusMessage')!r}"
    )
    native = sfn.describe_state_machine(stateMachineArn=identifier)
    assert json.loads(native["definition"]) == _DEF_V2, (
        f"the add-patch left the native definition at {native['definition']!r}"
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
