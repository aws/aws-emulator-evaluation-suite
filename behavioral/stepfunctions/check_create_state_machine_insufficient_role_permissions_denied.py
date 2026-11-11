"""create-state-machine-insufficient-role-permissions-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-insufficient-role-permissions-denied"
GROUP = "negative-classes"
SERVICES = ["stepfunctions"]

_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "states.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)

_SUFFICIENT_LOGS_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "logs:CreateLogDelivery",
                    "logs:CreateLogStream",
                    "logs:GetLogDelivery",
                    "logs:UpdateLogDelivery",
                    "logs:DeleteLogDelivery",
                    "logs:ListLogDeliveries",
                    "logs:PutLogEvents",
                    "logs:PutResourcePolicy",
                    "logs:DescribeResourcePolicies",
                    "logs:DescribeLogGroups",
                ],
                "Resource": "*",
            }
        ],
    }
)

# AccessDeniedException for a role Step Functions cannot assume yet: IAM propagation, not the
# missing log-delivery permissions this check grades.
_PROPAGATION_MESSAGE = (
    "Neither the global service principal states.amazonaws.com, nor the regional one is "
    "authorized to assume the provided role."
)

_INSUFFICIENT_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:ListAllMyBuckets"], "Resource": "*"}
        ],
    }
)


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine with a logging-enabled role lacking CloudWatch Logs delivery
    permissions is rejected with AccessDeniedException, and the same call succeeds once
    the role has the documented CloudWatch Logs permissions (cw-logs.html IAM policy)."""
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    logs = ctx.client("logs")

    log_group_name = ctx.unique_name("sim2real-sfn-lg-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    if not log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn.rstrip(":") + ":*"

    weak_role_name = ctx.unique_name("sim2real-sfn-weakrole-")
    weak_role_arn = iam.create_role(
        RoleName=weak_role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=weak_role_name))
    iam.put_role_policy(
        RoleName=weak_role_name, PolicyName="unrelated", PolicyDocument=_INSUFFICIENT_POLICY
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=weak_role_name, PolicyName="unrelated"))

    definition = json.dumps(
        {"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}}
    )
    logging_config = {
        "level": "ALL",
        "includeExecutionData": True,
        "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": log_group_arn}}],
    }

    weak_name = ctx.unique_name("sim2real-sfn-weaksm-")

    def _try_create_weak():
        sfn.create_state_machine(
            name=weak_name,
            definition=definition,
            roleArn=weak_role_arn,
            loggingConfiguration=logging_config,
        )

    # Poll while the brand-new role is not yet assumable (IAM propagation); once it is, the
    # request must still fail because the attached policy never grants logs perms.
    deadline = time.monotonic() + 90
    while True:
        code, message = _error(_try_create_weak)
        if message != _PROPAGATION_MESSAGE or time.monotonic() >= deadline:
            break
        time.sleep(3)
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code!r}"
    assert message == "The state machine IAM Role is not authorized to access the Log Destination", (
        f"unexpected AccessDeniedException message {message!r}"
    )

    # Effect absent: the state machine must not have been created.
    names = [sm["name"] for sm in sfn.list_state_machines(maxResults=1000).get("stateMachines", [])]
    assert weak_name not in names, f"expected {weak_name!r} absent from list_state_machines, found it present"

    # Positive control: same definition/logging config, but role has the documented
    # CloudWatch Logs delivery permissions -> CreateStateMachine must succeed.
    strong_role_name = ctx.unique_name("sim2real-sfn-strongrole-")
    strong_role_arn = iam.create_role(
        RoleName=strong_role_name,
        AssumeRolePolicyDocument=_TRUST_POLICY,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=strong_role_name))
    iam.put_role_policy(
        RoleName=strong_role_name, PolicyName="cwlogs", PolicyDocument=_SUFFICIENT_LOGS_POLICY
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=strong_role_name, PolicyName="cwlogs"))

    strong_name = ctx.unique_name("sim2real-sfn-strongsm-")
    # The strong role is just as new, so its AccessDeniedException is retried until IAM settles.
    deadline = time.monotonic() + 90
    while True:
        try:
            created_arn = sfn.create_state_machine(
                name=strong_name,
                definition=definition,
                roleArn=strong_role_arn,
                loggingConfiguration=logging_config,
                tags=[{"key": "sim2real", "value": "true"}],
            )["stateMachineArn"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException" or time.monotonic() >= deadline:
                raise AssertionError(f"positive control never succeeded, last error: {exc.response['Error']!r}")
            time.sleep(3)
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=created_arn))
    desc = sfn.describe_state_machine(stateMachineArn=created_arn)
    assert desc["status"] == "ACTIVE", f"expected status ACTIVE, got {desc['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
