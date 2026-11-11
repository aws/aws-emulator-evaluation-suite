"""resource-tag-condition-denies-tagged-activity-state-machine-and-its-executions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "resource-tag-condition-denies-tagged-activity-state-machine-and-its-executions"
GROUP = "enforcement"
SERVICES = ["stepfunctions"]

_SESSION_NAME = "sim2real-behav-restag-session"
_FORBIDDEN_KEY = "sim2real-forbidden"
_FORBIDDEN_VALUE = "blocked"
_PASS_DEFINITION = json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Pass", "End": True}}})


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An aws:ResourceTag/K=V deny refuses DescribeActivity/StartExecution/StartSyncExecution/
    DescribeExecution on a tagged activity or state machine; for an execution, the condition
    is evaluated against the owning state machine's tags, since an execution carries none.
    """
    sfn = ctx.client("stepfunctions")
    sts = ctx.client("sts")
    iam = ctx.client("iam")

    exec_role_arn = _create_sfn_exec_role(ctx, iam)
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "states:DescribeActivity",
                    "states:StartExecution",
                    "states:StartSyncExecution",
                    "states:DescribeExecution",
                ],
                "Resource": "*",
            },
            {
                "Effect": "Deny",
                "Action": [
                    "states:DescribeActivity",
                    "states:StartExecution",
                    "states:StartSyncExecution",
                    "states:DescribeExecution",
                ],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {f"aws:ResourceTag/{_FORBIDDEN_KEY}": _FORBIDDEN_VALUE}
                },
            },
        ],
    }
    role_arn, role_name = _create_role(ctx, iam, policy)
    as_role = _client_as(ctx, _assume(sts, role_arn))
    session_arn = f"arn:aws:sts::{ctx.account}:assumed-role/{role_name}/{_SESSION_NAME}"

    def denied(action: str, resource_arn: str) -> tuple[str, str]:
        return (
            "AccessDeniedException",
            f"User: {session_arn} is not authorized to perform: {action} on resource: "
            f"{resource_arn} with an explicit deny in an identity-based policy",
        )

    # ---- DescribeActivity: a tagged activity refuses, an untagged one does not. ----
    control_act_name = ctx.unique_name("sim2real-behav-restag-act-")
    control_act_arn = sfn.create_activity(
        name=control_act_name, tags=[{"key": "sim2real-other", "value": "allowed"}],
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=control_act_arn))

    tagged_act_name = ctx.unique_name("sim2real-behav-restag-act-")
    tagged_act_arn = sfn.create_activity(
        name=tagged_act_name, tags=[{"key": _FORBIDDEN_KEY, "value": _FORBIDDEN_VALUE}],
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=tagged_act_arn))

    # Positive control first: once this succeeds the role's policy has propagated, so the
    # refusals that follow are evaluations of the condition rather than a not-yet-effective grant.
    _poll_until_ok(
        lambda: as_role.describe_activity(activityArn=control_act_arn), timeout_s=240.0,
    )

    code, message = _error_code_and_message(lambda: as_role.describe_activity(activityArn=tagged_act_arn))
    assert (code, message) == denied("states:DescribeActivity", tagged_act_arn), (
        f"DescribeActivity on a tagged activity: expected "
        f"{denied('states:DescribeActivity', tagged_act_arn)!r}, got {(code, message)!r}"
    )

    # ---- StartExecution / StartSyncExecution: a tagged EXPRESS state machine refuses. ----
    control_express_arn = _create_state_machine(
        ctx, sfn, exec_role_arn, "EXPRESS", tags=[{"key": "sim2real-other", "value": "allowed"}],
    )
    tagged_express_arn = _create_state_machine(
        ctx, sfn, exec_role_arn, "EXPRESS", tags=[{"key": _FORBIDDEN_KEY, "value": _FORBIDDEN_VALUE}],
    )

    sync = as_role.start_sync_execution(stateMachineArn=control_express_arn, input="{}")
    assert sync["status"] == "SUCCEEDED", (
        f"the positive control's StartSyncExecution did not SUCCEED: {sync['status']!r}"
    )

    code, message = _error_code_and_message(
        lambda: as_role.start_execution(stateMachineArn=tagged_express_arn, input="{}")
    )
    assert (code, message) == denied("states:StartExecution", tagged_express_arn), (
        f"StartExecution on a tagged state machine: expected "
        f"{denied('states:StartExecution', tagged_express_arn)!r}, got {(code, message)!r}"
    )

    code, message = _error_code_and_message(
        lambda: as_role.start_sync_execution(stateMachineArn=tagged_express_arn, input="{}")
    )
    assert (code, message) == denied("states:StartSyncExecution", tagged_express_arn), (
        f"StartSyncExecution on a tagged state machine: expected "
        f"{denied('states:StartSyncExecution', tagged_express_arn)!r}, got {(code, message)!r}"
    )

    # ---- DescribeExecution: evaluated against the owning STANDARD state machine's tags. ----
    control_std_arn = _create_state_machine(
        ctx, sfn, exec_role_arn, "STANDARD", tags=[{"key": "sim2real-other", "value": "allowed"}],
    )
    tagged_std_arn = _create_state_machine(
        ctx, sfn, exec_role_arn, "STANDARD", tags=[{"key": _FORBIDDEN_KEY, "value": _FORBIDDEN_VALUE}],
    )

    # Started with the unrestricted client: a execution carries no tags of its own, only an
    # inherited relationship to its state machine, so this call never needs the restricted role.
    control_exec_arn = sfn.start_execution(stateMachineArn=control_std_arn, input="{}")["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=control_exec_arn))
    tagged_exec_arn = sfn.start_execution(stateMachineArn=tagged_std_arn, input="{}")["executionArn"]
    ctx.on_cleanup(lambda: sfn.stop_execution(executionArn=tagged_exec_arn))

    desc = _poll_until_ok(lambda: as_role.describe_execution(executionArn=control_exec_arn), timeout_s=60.0)
    assert desc["executionArn"] == control_exec_arn, (
        f"DescribeExecution on an untagged state machine's execution returned the wrong execution: {desc!r}"
    )

    code, message = _error_code_and_message(
        lambda: as_role.describe_execution(executionArn=tagged_exec_arn)
    )
    assert (code, message) == denied("states:DescribeExecution", tagged_exec_arn), (
        f"DescribeExecution of a tagged state machine's execution: expected "
        f"{denied('states:DescribeExecution', tagged_exec_arn)!r}, got {(code, message)!r}"
    )


def _create_state_machine(ctx, sfn, exec_role_arn: str, sm_type: str, *, tags: list[dict]) -> str:
    name = ctx.unique_name(f"sim2real-behav-restag-{sm_type.lower()}-")
    arn = sfn.create_state_machine(
        name=name, definition=_PASS_DEFINITION, roleArn=exec_role_arn, type=sm_type, tags=tags,
    )["stateMachineArn"]
    ctx.on_cleanup(_teardown(lambda: sfn.delete_state_machine(stateMachineArn=arn)))
    return arn


def _create_sfn_exec_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-behav-restag-execrole-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    return role["Role"]["Arn"]


def _create_role(ctx, iam, policy) -> tuple[str, str]:
    role_name = ctx.unique_name("sim2real-behav-restag-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{ctx.account}:root"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.put_role_policy(RoleName=role_name, PolicyName="restricted", PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(
        _teardown(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="restricted"),
            "NoSuchEntity",
        )
    )
    return role["Role"]["Arn"], role_name


def _assume(sts, role_arn: str, timeout_s: float = 150.0, interval_s: float = 2.0) -> dict:
    """Assume the freshly created role, retrying while its trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return sts.assume_role(RoleArn=role_arn, RoleSessionName=_SESSION_NAME)["Credentials"]
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "AccessDenied":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"assume-role never succeeded (trust policy propagation?): {last_err}")


def _client_as(ctx, creds: dict):
    return ctx.client(
        "stepfunctions",
        creds={
            "aws_access_key_id": creds["AccessKeyId"],
            "aws_secret_access_key": creds["SecretAccessKey"],
            "aws_session_token": creds["SessionToken"],
        },
    )


def _poll_until_ok(fn, *, timeout_s: float, interval_s: float = 2.0):
    """Retry ``fn`` while IAM is still propagating the policy that should allow it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in ("AccessDeniedException", "UnrecognizedClientException", "InvalidClientTokenId") or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _error_code_and_message(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
