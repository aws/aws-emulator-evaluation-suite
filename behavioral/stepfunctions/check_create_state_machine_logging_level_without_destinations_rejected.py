"""create-state-machine-logging-level-without-destinations-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-logging-level-without-destinations-rejected"
GROUP = "execution_logging"
SERVICES = ["stepfunctions", "logs", "iam"]

_TRUST_POLICY = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "states.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
})

_PASS_DEFINITION = json.dumps({
    "StartAt": "Done",
    "States": {"Done": {"Type": "Succeed"}},
})


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected CreateStateMachine to be refused, but it succeeded: {result!r}")


_LOG_DELIVERY_ACTIONS = [
    "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery",
    "logs:DeleteLogDelivery", "logs:ListLogDeliveries", "logs:PutResourcePolicy",
    "logs:DescribeResourcePolicies", "logs:DescribeLogGroups",
]


def _create_role(ctx) -> str:
    """A states.amazonaws.com-assumable role carrying the log-delivery actions documented
    at cw-logs.html; those actions take no resource scope."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-sfnlogrole-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.put_role_policy(
        RoleName=name, PolicyName="logging",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": _LOG_DELIVERY_ACTIONS, "Resource": "*"}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=name, PolicyName="logging"))
    return arn


def _create_log_group(ctx) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name("/aws/vendedlogs/states/sim2real-behav-")
    logs.create_log_group(logGroupName=name, tags={"sim2real": "1"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=name))
    account = ctx.client("sts").get_caller_identity()["Account"]
    return f"arn:aws:logs:{ctx.region}:{account}:log-group:{name}:*"


def _create_state_machine(ctx, sfn, name: str, role_arn: str, logging: dict | None) -> str:
    """CreateStateMachine, retrying only the AccessDeniedException raised while the freshly
    created role's trust propagates."""
    kwargs = {"name": name, "definition": _PASS_DEFINITION, "roleArn": role_arn,
              "tags": [{"key": "sim2real", "value": "1"}]}
    if logging is not None:
        kwargs["loggingConfiguration"] = logging
    deadline = time.monotonic() + 90.0
    while True:
        try:
            arn = sfn.create_state_machine(**kwargs)["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() > deadline:
                raise
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
    return arn


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine with a logging level other than OFF and no destinations fails with
    InvalidLoggingConfiguration and the exact message and creates nothing, while the same
    level with a destination is accepted and reads back from DescribeStateMachine."""
    sfn = ctx.client("stepfunctions")
    role_arn = _create_role(ctx)
    bad_name = ctx.unique_name("sim2real-behav-sfnlog-bad-")

    code, message = _error(lambda: _create_state_machine(
        ctx, sfn, bad_name, role_arn,
        {"level": "ALL", "includeExecutionData": True, "destinations": []},
    ))
    assert code == "InvalidLoggingConfiguration", (
        f"expected InvalidLoggingConfiguration, got {code!r}: {message!r}"
    )
    expected = "Invalid Logging Configuration: Must specify exactly one Log Destination."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    paginator = sfn.get_paginator("list_state_machines")
    names = {m["name"] for page in paginator.paginate() for m in page["stateMachines"]}
    assert bad_name not in names, f"a refused CreateStateMachine call left {bad_name!r} behind"

    group_arn = _create_log_group(ctx)
    good_name = ctx.unique_name("sim2real-behav-sfnlog-ok-")
    good_arn = _create_state_machine(ctx, sfn, good_name, role_arn, {
        "level": "ALL", "includeExecutionData": True,
        "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": group_arn}}],
    })
    described = sfn.describe_state_machine(stateMachineArn=good_arn)
    assert described["loggingConfiguration"]["level"] == "ALL", (
        f"DescribeStateMachine returned logging level {described['loggingConfiguration']!r}, expected ALL"
    )
    assert described["loggingConfiguration"]["destinations"][0]["cloudWatchLogsLogGroup"]["logGroupArn"] == group_arn, (
        f"DescribeStateMachine returned destinations {described['loggingConfiguration']['destinations']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
