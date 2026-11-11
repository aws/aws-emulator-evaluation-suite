"""statemachinequalifier-condition-restricts-qualifier-value-not-its-absence."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "statemachinequalifier-condition-restricts-qualifier-value-not-its-absence"
GROUP = "permission-boundary"
SERVICES = ["stepfunctions"]

_DEFINITION = json.dumps({"StartAt": "P", "States": {"P": {"Type": "Pass", "End": True}}})
_IAM_RETRY_DEADLINE_S = 90.0


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ForAllValues:StringEquals condition on states:StateMachineQualifier denies
    StartExecution/DescribeStateMachine for a qualifier outside the allowed set (naming the
    unqualified ARN) but not an unqualified call, whose absent context key is vacuously allowed."""
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    sfn = ctx.client("stepfunctions")
    account = ctx.account

    exec_role_arn = _execution_role(ctx, iam)
    sm_arn = _create_state_machine(ctx, sfn, exec_role_arn)
    version_arn = sfn.publish_state_machine_version(stateMachineArn=sm_arn)["stateMachineVersionArn"]
    version_qualifier = version_arn.rsplit(":", 1)[1]
    alias_name = ctx.unique_name("sim2real-sfnq-alias-")[:80]
    alias_arn = sfn.create_state_machine_alias(
        name=alias_name, routingConfiguration=[{"stateMachineVersionArn": version_arn, "weight": 100}],
    )["stateMachineAliasArn"]
    ctx.on_cleanup(lambda: sfn.delete_state_machine_alias(stateMachineAliasArn=alias_arn))

    caller_role, caller_role_arn = _caller_role(
        ctx, iam, account,
        actions=["states:StartExecution", "states:DescribeStateMachine"],
        resource=sm_arn, allowed_qualifiers=[alias_name, version_qualifier],
    )
    session_name = ctx.unique_name("sim2real-sfnq-")[:64]
    assumed_arn, caller_sfn = _assume_session(ctx, sts, caller_role_arn, session_name)

    qualified_start = _retry_iam_propagation(
        lambda: caller_sfn.start_execution(stateMachineArn=alias_arn, input="{}")
    )
    ctx.on_cleanup(lambda: _stop_if_running(sfn, qualified_start["executionArn"]))

    wrong_qualifier = ctx.unique_name("sim2real-sfnq-wrong-")[:80]
    code, message = _error(
        lambda: caller_sfn.start_execution(stateMachineArn=f"{sm_arn}:{wrong_qualifier}", input="{}")
    )
    assert code == "AccessDeniedException", (
        f"StartExecution with a qualifier outside the allowed set must be denied; got {code!r}"
    )
    assert message == (
        f"User: {assumed_arn} is not authorized to perform: states:StartExecution on resource: "
        f"{sm_arn} because no identity-based policy allows the states:StartExecution action"
    ), f"unexpected AccessDeniedException message: {message!r}"

    # The documented nuance: an unqualified call carries no states:StateMachineQualifier context
    # key at all, so ForAllValues:StringEquals is vacuously satisfied and the call is ALLOWED.
    unqualified_exec = caller_sfn.start_execution(stateMachineArn=sm_arn, input="{}")["executionArn"]
    ctx.on_cleanup(lambda: _stop_if_running(sfn, unqualified_exec))
    unqualified_final = _wait_terminal(sfn, unqualified_exec)
    assert unqualified_final["status"] == "SUCCEEDED", (
        f"an unqualified StartExecution must succeed under this condition (absence, not a listed "
        f"value); got {unqualified_final['status']!r}"
    )

    desc = caller_sfn.describe_state_machine(stateMachineArn=f"{sm_arn}:{version_qualifier}")
    assert desc["stateMachineArn"] == version_arn, (
        f"DescribeStateMachine on the version-qualified ARN must report that ARN back; got "
        f"{desc.get('stateMachineArn')!r}"
    )
    other_version_qualifier = str(int(version_qualifier) + 1)
    code, message = _error(
        lambda: caller_sfn.describe_state_machine(
            stateMachineArn=f"{sm_arn}:{other_version_qualifier}")
    )
    assert code == "AccessDeniedException", (
        f"DescribeStateMachine with a version outside the allowed set must be denied; got {code!r}"
    )
    assert message == (
        f"User: {assumed_arn} is not authorized to perform: states:DescribeStateMachine on "
        f"resource: {sm_arn} because no identity-based policy allows the "
        f"states:DescribeStateMachine action"
    ), f"unexpected AccessDeniedException message: {message!r}"


def _execution_role(ctx, iam) -> str:
    name = ctx.unique_name("sim2real-sfnq-exrole-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"Service": "states.amazonaws.com"},
                            "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    return arn


def _caller_role(ctx, iam, account, *, actions, resource, allowed_qualifiers):
    name = ctx.unique_name("sim2real-sfnq-caller-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                            "Action": "sts:AssumeRole"}],
        }),
        Tags=[{"Key": "sim2real", "Value": CHECK[:250]}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    policy_name = "sim2real-sfnq-caller"
    iam.put_role_policy(
        RoleName=name, PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow", "Action": actions, "Resource": resource,
                "Condition": {"ForAllValues:StringEquals":
                              {"states:StateMachineQualifier": allowed_qualifiers}},
            }],
        }),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name))
    return name, arn


def _assume_session(ctx, sts, role_arn, session_name):
    deadline = time.monotonic() + _IAM_RETRY_DEADLINE_S
    last = None
    while time.monotonic() < deadline:
        try:
            resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDenied":
                raise
            last = exc
            time.sleep(3.0)
    else:
        raise AssertionError(f"AssumeRole on the fresh caller role never succeeded: {last!r}")
    assumed_arn = resp["AssumedRoleUser"]["Arn"]
    creds = resp["Credentials"]
    client = ctx.client("stepfunctions", creds={
        "aws_access_key_id": creds["AccessKeyId"],
        "aws_secret_access_key": creds["SecretAccessKey"],
        "aws_session_token": creds["SessionToken"],
    })
    return assumed_arn, client


_PROPAGATION_CODES = ("AccessDeniedException", "UnrecognizedClientException")


def _retry_iam_propagation(fn, timeout_s: float = _IAM_RETRY_DEADLINE_S):
    """First use of a freshly attached inline policy, retrying two propagation windows: the
    policy itself (AccessDeniedException) and the freshly assumed session credentials, which can
    briefly answer UnrecognizedClientException before STS propagates them region-wide."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in _PROPAGATION_CODES:
                raise
            last = exc
            time.sleep(3.0)
    raise AssertionError(f"the caller role's policy never took effect: {last!r}")


def _create_state_machine(ctx, sfn, role_arn: str, timeout_s: float = 90.0) -> str:
    name = ctx.unique_name("sim2real-sfnq-sm-")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            arn = sfn.create_state_machine(
                name=name, definition=_DEFINITION, roleArn=role_arn, type="STANDARD",
                tags=[{"key": "sim2real", "value": CHECK[:250]}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
            last = exc
            time.sleep(3.0)
    else:
        raise AssertionError(f"CreateStateMachine still AccessDenied after {timeout_s}s: {last}")
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


def _wait_terminal(sfn, exec_arn: str, timeout_s: float = 90.0, poll_s: float = 2.0) -> dict:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sfn.describe_execution(executionArn=exec_arn)
        if last["status"] != "RUNNING":
            return last
        time.sleep(poll_s)
    raise AssertionError(f"execution {exec_arn} still RUNNING after {timeout_s}s: {last!r}")


def _stop_if_running(sfn, exec_arn: str) -> None:
    if sfn.describe_execution(executionArn=exec_arn)["status"] == "RUNNING":
        sfn.stop_execution(executionArn=exec_arn)


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
