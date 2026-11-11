"""iam-resource-prefix-on-execution-grants-execution-ops-not-start."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iam-resource-prefix-on-execution-grants-execution-ops-not-start"
GROUP = "permissions-boundaries"
SERVICES = ["iam", "stepfunctions"]

_DEFINITION = json.dumps(
    {"StartAt": "Wait", "States": {"Wait": {"Type": "Wait", "Seconds": 300, "End": True}}}
)

# Codes that mean "the grant (or the access key itself) has not propagated yet", not "the
# boundary failed" -- only used on the leg that expects SUCCESS.
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


def _stop_all(ctx, arns: list[str]) -> None:
    """Best-effort stop for every execution that might still be RUNNING, before delete."""
    sfn = ctx.client("stepfunctions")
    for arn in arns:
        try:
            sfn.stop_execution(executionArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ExecutionDoesNotExist":
                raise


def _delete_state_machine(ctx, arn: str, exec_arns: list[str]) -> None:
    """Stop any RUNNING executions, delete the machine and wait until it is gone."""
    sfn = ctx.client("stepfunctions")
    _stop_all(ctx, exec_arns)
    try:
        sfn.delete_state_machine(stateMachineArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
            raise
        return
    deadline = time.monotonic() + 180.0
    while True:
        try:
            sfn.describe_state_machine(stateMachineArn=arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "StateMachineDoesNotExist":
                raise
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"state machine {arn} still present 180s after delete")
        time.sleep(2)


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """states:* on execution:*:<prefix>* allows Describe/Stop/GetExecutionHistory/
    DescribeStateMachineForExecution on a matching execution name and denies a non-matching one;
    StartExecution stays denied either way since it authorizes against the state machine ARN.
    """
    iam = ctx.client("iam")
    sfn = ctx.client("stepfunctions")
    account = ctx.account
    region = ctx.region

    exec_role_name = ctx.unique_name("sim2real-sfnexecprefix-role-")
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

    sm_name = ctx.unique_name("sim2real-sfnexecprefix-sm-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            sm_arn = sfn.create_state_machine(
                name=sm_name, definition=_DEFINITION, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            msg = str(exc)
            if ("not authorized to assume" not in msg
                    and "assume the provided role" not in msg) or time.monotonic() >= deadline:
                raise
        time.sleep(2)

    exec_arns_box: list[str] = []
    ctx.on_cleanup(lambda: _delete_state_machine(ctx, sm_arn, list(exec_arns_box)))

    base = ctx.unique_name("sim2real-sfnexecprefix-")
    exec_match_name = f"{base}match"
    exec_other_name = ctx.unique_name("sim2real-sfnexecother-") + "nomatch"

    exec_match_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=exec_match_name, input="{}"
    )["executionArn"]
    exec_arns_box.append(exec_match_arn)
    exec_other_arn = sfn.start_execution(
        stateMachineArn=sm_arn, name=exec_other_name, input="{}"
    )["executionArn"]
    exec_arns_box.append(exec_other_arn)

    user_name = ctx.unique_name("sim2real-sfnexecprefix-user-")
    iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_user_and_keys(ctx, user_name))

    resource_pattern = f"arn:aws:states:{region}:{account}:execution:*:{base}*"
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

    # ---- BEAT 1: positive control -- Describe on the MATCHING execution name succeeds. ----
    box: dict[str, dict] = {}

    def _try_describe_match():
        try:
            box["desc"] = as_user.describe_execution(executionArn=exec_match_arn)
        except ClientError as exc:
            return exc.response["Error"]["Code"]
        return "UNEXPECTED_SUCCESS"

    first = _poll_until(
        _try_describe_match, lambda c: c not in _UNCONVERGED,
        timeout_s=_PROPAGATION_TIMEOUT_S,
        description="the execution-prefix grant becoming effective for DescribeExecution",
    )
    assert first == "UNEXPECTED_SUCCESS", (
        f"positive control: states:* on execution:*:{base}* must allow DescribeExecution "
        f"on the matching-name execution; got {first!r}"
    )
    assert box["desc"]["status"] == "RUNNING", (
        f"expected the long Wait execution to still be RUNNING, got {box['desc']['status']!r}"
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

    # ---- BEAT 2: the NON-matching execution name -- denied, immediately. ----
    code, message = _error(lambda: as_user.describe_execution(executionArn=exec_other_arn))
    _access_denied("states:DescribeExecution", exec_other_arn, code, message)

    # ---- BEAT 3: GetExecutionHistory and DescribeStateMachineForExecution follow the same
    # resource-level split. ----
    hist = as_user.get_execution_history(executionArn=exec_match_arn)
    assert hist["events"], "GetExecutionHistory on the matching execution returned no events"

    code, message = _error(lambda: as_user.get_execution_history(executionArn=exec_other_arn))
    _access_denied("states:GetExecutionHistory", exec_other_arn, code, message)

    desc_for = as_user.describe_state_machine_for_execution(executionArn=exec_match_arn)
    assert desc_for["stateMachineArn"] == sm_arn, (
        f"DescribeStateMachineForExecution returned {desc_for['stateMachineArn']!r}, "
        f"expected {sm_arn!r}"
    )

    code, message = _error(
        lambda: as_user.describe_state_machine_for_execution(executionArn=exec_other_arn)
    )
    _access_denied("states:DescribeStateMachineForExecution", exec_other_arn, code, message)

    # ---- BEAT 4: StartExecution authorizes against the STATE MACHINE arn, a resource type
    # this policy never names -- denied even though the chosen execution NAME matches the
    # prefix, and even for the non-matching name too. ----
    code, message = _error(
        lambda: as_user.start_execution(
            stateMachineArn=sm_arn, name=f"{base}newattempt", input="{}"
        )
    )
    _access_denied("states:StartExecution", sm_arn, code, message)

    # ---- BEAT 5: StopExecution on the MATCHING execution succeeds, and its effect is real:
    # the execution actually transitions to ABORTED. ----
    as_user.stop_execution(executionArn=exec_match_arn)

    stopped = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_match_arn),
        lambda d: d["status"] != "RUNNING", timeout_s=60.0,
        description="the matching execution reaching a terminal state after StopExecution",
    )
    assert stopped["status"] == "ABORTED", (
        f"expected ABORTED after StopExecution, got {stopped['status']!r}"
    )

    # ---- BEAT 6: StopExecution on the NON-matching execution -- denied, and it is left
    # untouched (still RUNNING). ----
    code, message = _error(lambda: as_user.stop_execution(executionArn=exec_other_arn))
    _access_denied("states:StopExecution", exec_other_arn, code, message)

    still_running = sfn.describe_execution(executionArn=exec_other_arn)
    assert still_running["status"] == "RUNNING", (
        f"the denied StopExecution must have no effect; status is {still_running['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
