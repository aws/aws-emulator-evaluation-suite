"""iam-resource-prefix-on-state-machine-scopes-sm-ops-not-executions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-resource-prefix-on-state-machine-scopes-sm-ops-not-executions"
GROUP = "permissions-boundaries"
SERVICES = ["iam", "stepfunctions"]

_DEFINITION = json.dumps(
    {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}
)

# Codes that mean "the grant (or the access key itself) has not propagated yet", not "the
# boundary failed" -- only used on the leg that expects SUCCESS, where a denial is
# indistinguishable from an unpropagated grant or an unpropagated key.
_UNCONVERGED = frozenset({
    "AccessDeniedException", "InvalidClientTokenId", "UnrecognizedClientException",
    "SignatureDoesNotMatch",
})

_PROPAGATION_TIMEOUT_S = 120.0


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_user_and_keys(ctx, user_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for key in iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", []):
            iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
        for pname in iam.list_user_policies(UserName=user_name).get("PolicyNames", []):
            iam.delete_user_policy(UserName=user_name, PolicyName=pname)
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_state_machines(ctx, arns: list[str]) -> None:
    """Issue DeleteStateMachine for every arn FIRST, then wait on all of them together: deletion is
    asynchronous, and the cost of waiting on N machines is the max of their waits, not the sum."""
    sfn = ctx.client("stepfunctions")
    for arn in arns:
        try:
            paginator = sfn.get_paginator("list_executions")
            for page in paginator.paginate(stateMachineArn=arn, statusFilter="RUNNING"):
                for ex in page.get("executions", []):
                    try:
                        sfn.stop_execution(executionArn=ex["executionArn"])
                    except ClientError as exc:
                        if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
                            raise
            sfn.delete_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                raise
    pending = set(arns)
    budget_s = 180.0
    deadline = time.monotonic() + budget_s
    while pending:
        gone = set()
        for arn in pending:
            try:
                sfn.describe_state_machine(stateMachineArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                    raise
                gone.add(arn)
        pending -= gone
        if not pending:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"state machine(s) still present {budget_s}s after DeleteStateMachine: "
                f"{sorted(pending)!r}"
            )
        time.sleep(2)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """states:* on stateMachine:<prefix>* allows Describe on a matching name, denies a
    non-matching one, and still denies DescribeExecution/StopExecution/GetExecutionHistory/
    RedriveExecution/ListStateMachines/CreateActivity -- each a different resource type.
    """
    iam = ctx.client("iam")
    sfn = ctx.client("stepfunctions")
    account = ctx.account
    region = ctx.region

    base = ctx.unique_name("sim2real-sfnprefix-")
    sm_match_name = f"{base}match"
    sm_other_name = ctx.unique_name("sim2real-sfnother-") + "nomatch"

    exec_role_name = ctx.unique_name("sim2real-sfnprefix-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
             "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=exec_role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, exec_role_name))

    def _create_sm(name: str) -> str:
        deadline = time.monotonic() + 90.0
        while True:
            try:
                return sfn.create_state_machine(
                    name=name, definition=_DEFINITION, roleArn=role_arn, type="STANDARD",
                    tags=[{"key": "sim2real", "value": CHECK}],
                )["stateMachineArn"]
            except ClientError as exc:
                msg = str(exc)
                if ("not authorized to assume" not in msg
                        and "assume the provided role" not in msg) or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    sm_match_arn = _create_sm(sm_match_name)
    sm_other_arn = _create_sm(sm_other_name)
    ctx.on_cleanup(lambda: _delete_state_machines(ctx, [sm_match_arn, sm_other_arn]))

    user_name = ctx.unique_name("sim2real-sfnprefix-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_and_keys(ctx, user_name))

    resource_pattern = f"arn:aws:states:{region}:{account}:stateMachine:{base}*"
    iam.put_user_policy(
        UserName=user_name,
        PolicyName="prefix-scope",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "states:*", "Resource": resource_pattern}
            ],
        }),
    )
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    as_user = ctx.client(
        "stepfunctions",
        creds={"aws_access_key_id": key["AccessKeyId"], "aws_secret_access_key": key["SecretAccessKey"]},
    )

    # ---- BEAT 1: positive control -- Describe on the MATCHING name succeeds. ----
    # A denial here is indistinguishable from an unpropagated grant, so this leg polls.
    box: dict[str, dict] = {}

    def _try_describe_match():
        try:
            box["desc"] = as_user.describe_state_machine(stateMachineArn=sm_match_arn)
        except ClientError as exc:
            return exc.response["Error"]["Code"]
        return "UNEXPECTED_SUCCESS"

    first = _poll_until(
        _try_describe_match, lambda c: c not in _UNCONVERGED,
        timeout_s=_PROPAGATION_TIMEOUT_S,
        description="the stateMachine-prefix grant becoming effective for DescribeStateMachine",
    )
    assert first == "UNEXPECTED_SUCCESS", (
        f"positive control: states:* on stateMachine:{base}* must allow "
        f"DescribeStateMachine on the matching-name machine; got {first!r}"
    )
    assert box["desc"]["name"] == sm_match_name, (
        f"expected name {sm_match_name!r}, got {box['desc']['name']!r}"
    )

    user_arn = f"arn:aws:iam::{account}:user/{user_name}"

    def _access_denied(action: str, resource_arn: str, actual_code, actual_message) -> None:
        assert actual_code == "AccessDeniedException", (
            f"expected AccessDeniedException for {action} on {resource_arn!r}, got "
            f"{actual_code!r}: {actual_message!r}"
        )
        expected = (
            f"User: {user_arn} is not authorized to perform: {action} on resource: "
            f"{resource_arn} because no identity-based policy allows the {action} action"
        )
        assert actual_message == expected, (
            f"message for {action} was {actual_message!r}, expected {expected!r}"
        )

    # ---- BEAT 2: same action, the NON-matching name -- denied, immediately (no propagation
    # ambiguity: the policy never names this ARN). ----
    code, message = _error(lambda: as_user.describe_state_machine(stateMachineArn=sm_other_arn))
    _access_denied("states:DescribeStateMachine", sm_other_arn, code, message)

    # ---- BEAT 3: an execution of the MATCHING machine is a different resource type --
    # Describe/Stop/GetExecutionHistory/Redrive on it are denied even though the owning state
    # machine matches the granted prefix. ----
    exec_arn = sfn.start_execution(stateMachineArn=sm_match_arn, input="{}")["executionArn"]

    def _probe_terminal():
        return sfn.describe_execution(executionArn=exec_arn)

    desc = _poll_until(
        _probe_terminal, lambda d: d["status"] in ("SUCCEEDED", "FAILED"), timeout_s=60.0,
        description="the control execution reaching a terminal state",
    )
    assert desc["status"] == "SUCCEEDED", f"control execution ended {desc['status']!r}, not SUCCEEDED"

    code, message = _error(lambda: as_user.describe_execution(executionArn=exec_arn))
    _access_denied("states:DescribeExecution", exec_arn, code, message)

    code, message = _error(lambda: as_user.stop_execution(executionArn=exec_arn))
    _access_denied("states:StopExecution", exec_arn, code, message)

    code, message = _error(lambda: as_user.get_execution_history(executionArn=exec_arn))
    _access_denied("states:GetExecutionHistory", exec_arn, code, message)

    code, message = _error(lambda: as_user.redrive_execution(executionArn=exec_arn))
    _access_denied("states:RedriveExecution", exec_arn, code, message)

    # ---- BEAT 4: ListStateMachines and CreateActivity never carry a resource of this type at
    # all -- states:* on a stateMachine ARN pattern grants neither. ----
    code, message = _error(lambda: as_user.list_state_machines())
    _access_denied(
        "states:ListStateMachines", f"arn:aws:states:{region}:{account}:stateMachine:*",
        code, message,
    )

    activity_name = ctx.unique_name("sim2real-sfnprefix-shouldnotexist-")
    activity_created: dict[str, str] = {}

    def _try_create_activity():
        resp = as_user.create_activity(name=activity_name)
        activity_created["arn"] = resp["activityArn"]
        return resp

    code, message = _error(_try_create_activity)
    if "arn" in activity_created:
        ctx.client("stepfunctions").delete_activity(activityArn=activity_created["arn"])
        raise AssertionError(
            f"CreateActivity unexpectedly SUCCEEDED for a principal granted only "
            f"stateMachine:{base}*: {activity_created['arn']!r}"
        )
    _access_denied(
        "states:CreateActivity", f"arn:aws:states:{region}:{account}:activity:{activity_name}",
        code, message,
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
