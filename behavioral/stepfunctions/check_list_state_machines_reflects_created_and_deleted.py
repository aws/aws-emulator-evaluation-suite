"""list-state-machines-reflects-created-and-deleted."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-state-machines-reflects-created-and-deleted"
GROUP = "state-machine"
SERVICES = ["stepfunctions"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListStateMachines includes newly created machines and (eventually)
    excludes ones that have been deleted."""
    role_arn = _create_sfn_role(ctx)
    name = ctx.unique_name("sim2real-sfn-")
    sm_arn = _create_state_machine(ctx, role_arn, _SIMPLE_DEFINITION, name=name)
    sfn = ctx.client("stepfunctions")

    def _find_in_listing():
        next_token = None
        while True:
            kwargs = {"nextToken": next_token} if next_token else {}
            page = sfn.list_state_machines(**kwargs)
            for m in page["stateMachines"]:
                if m["stateMachineArn"] == sm_arn:
                    return m
            next_token = page.get("nextToken")
            if not next_token:
                return None

    found = _find_in_listing()
    assert found is not None, f"{sm_arn} missing from ListStateMachines right after creation"
    assert found["name"] == name, f"expected name {name!r}, got {found['name']!r}"

    sfn.delete_state_machine(stateMachineArn=sm_arn)

    absent = _poll_until(
        lambda: _find_in_listing(),
        lambda m: m is None,
        timeout_s=300.0,
        interval_s=5.0,
    )
    assert absent is None, f"{sm_arn} still present in ListStateMachines after delete: {absent}"

    code, message = _error_code(lambda: sfn.describe_state_machine(stateMachineArn=sm_arn))
    assert code == "StateMachineDoesNotExist", f"expected StateMachineDoesNotExist, got {code}"
    expected_message = f"State Machine Does Not Exist: '{sm_arn}'"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


_SIMPLE_DEFINITION = {
    "Comment": "simple",
    "StartAt": "PassState",
    "States": {"PassState": {"Type": "Pass", "Result": "ok", "End": True}},
}

_SFN_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_SFN_INLINE_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "states:StartExecution",
                    "states:DescribeExecution",
                    "states:StopExecution",
                    "states:RedriveExecution",
                    "states:DescribeStateMachine",
                ],
                "Resource": "*",
            }
        ],
    }
)


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_sfn_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sfn-role-")
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_SFN_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    iam.put_role_policy(RoleName=role_name, PolicyName="sfn-inline", PolicyDocument=_SFN_INLINE_POLICY)

    def _cleanup():
        _swallow(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sfn-inline"))
        _swallow(lambda: iam.delete_role(RoleName=role_name))

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_state_machine(ctx, role_arn, definition, *, name=None, sm_type="STANDARD", register_cleanup=True):
    from botocore.exceptions import ClientError

    sfn = ctx.client("stepfunctions")
    name = name or ctx.unique_name("sim2real-sfn-")
    deadline = time.monotonic() + 60.0
    last_err = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = sfn.create_state_machine(
                name=name,
                definition=json.dumps(definition),
                roleArn=role_arn,
                type=sm_type,
                tags=[{"key": "sim2real", "value": CHECK}],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "AccessDeniedException":
                last_err = exc
                time.sleep(3)
                continue
            raise
    if resp is None:
        raise AssertionError(f"could not create state machine after role propagation wait: {last_err}")
    arn = resp["stateMachineArn"]
    if register_cleanup:
        ctx.on_cleanup(lambda: _swallow(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
