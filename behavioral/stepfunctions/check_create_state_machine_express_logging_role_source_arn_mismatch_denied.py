"""create-state-machine-express-logging-role-source-arn-mismatch-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-state-machine-express-logging-role-source-arn-mismatch-denied"
GROUP = "negative-classes"
SERVICES = ["stepfunctions"]

_DEFINITION = json.dumps({"StartAt": "Pass", "States": {"Pass": {"Type": "Pass", "End": True}}})


def _trust_policy(source_arn: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "states.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"ArnEquals": {"aws:SourceArn": source_arn}},
                }
            ],
        }
    )


_DENIAL_MESSAGE = (
    "Neither the global service principal states.amazonaws.com, nor the regional one is "
    "authorized to assume the provided role."
)

# Both roles carry the CloudWatch Logs delivery permissions logging needs, so the SourceArn
# condition is the only difference between them.
_LOGS_POLICY = json.dumps(
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


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _sm_arn(ctx, name: str) -> str:
    return f"arn:aws:states:{ctx.region}:{ctx.account}:stateMachine:{name}"


def _create_role(ctx, iam, name_prefix: str, source_arn: str) -> str:
    role_name = ctx.unique_name(name_prefix)
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_trust_policy(source_arn),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(RoleName=role_name, PolicyName="cwlogs", PolicyDocument=_LOGS_POLICY)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="cwlogs"))
    return role_arn


def _lists_state_machine(sfn, name) -> bool:
    paginator = sfn.get_paginator("list_state_machines")
    for page in paginator.paginate():
        if any(sm["name"] == name for sm in page["stateMachines"]):
            return True
    return False


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStateMachine (EXPRESS, logging enabled) with a role whose trust policy's
    aws:SourceArn condition names a different state machine is denied AccessDeniedException,
    permanently rather than transiently, while a role scoped to the real ARN succeeds.
    """
    sfn = ctx.client("stepfunctions")
    iam = ctx.client("iam")
    logs = ctx.client("logs")

    log_group_name = ctx.unique_name("sim2real-sfn-lg-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"][0]["arn"]
    if not log_group_arn.endswith(":*"):
        log_group_arn = log_group_arn.rstrip(":") + ":*"
    logging_config = {
        "level": "ALL",
        "includeExecutionData": True,
        "destinations": [{"cloudWatchLogsLogGroup": {"logGroupArn": log_group_arn}}],
    }

    # The mismatched role's condition names a state machine that is never created, so the
    # mismatch can never clear by propagation: it is a permanent denial, not a transient one.
    decoy_name = ctx.unique_name("sim2real-sfn-decoysm-")
    mismatched_role_arn = _create_role(ctx, iam, "sim2real-sfn-mismatchrole-", _sm_arn(ctx, decoy_name))
    bad_name = ctx.unique_name("sim2real-sfn-badsm-")

    # Positive control, created at the same time: a role whose condition names the real ARN the
    # state machine will get.
    good_name = ctx.unique_name("sim2real-sfn-goodsm-")
    good_role_arn = _create_role(ctx, iam, "sim2real-sfn-matchrole-", _sm_arn(ctx, good_name))

    def _try_create_bad():
        arn = sfn.create_state_machine(
            name=bad_name,
            definition=_DEFINITION,
            roleArn=mismatched_role_arn,
            type="EXPRESS",
            loggingConfiguration=logging_config,
        )["stateMachineArn"]
        ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=arn))
        return arn

    # Interleave both creates so the matched twin's eventual success marks the moment ordinary
    # IAM propagation has cleared; the mismatched one is sampled on every round, before and after
    # that moment.
    bad_results = []
    created_arn = None
    deadline = time.monotonic() + 90
    while created_arn is None and time.monotonic() < deadline:
        bad_results.append(_error(_try_create_bad))
        try:
            created_arn = sfn.create_state_machine(
                name=good_name,
                definition=_DEFINITION,
                roleArn=good_role_arn,
                type="EXPRESS",
                loggingConfiguration=logging_config,
                tags=[{"key": "sim2real", "value": "true"}],
            )["stateMachineArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "AccessDeniedException":
                raise
        time.sleep(3)
    assert created_arn is not None, (
        f"positive control (matching SourceArn) never succeeded within 90s, bad results: {bad_results!r}"
    )
    ctx.on_cleanup(lambda: sfn.delete_state_machine(stateMachineArn=created_arn))
    assert created_arn == _sm_arn(ctx, good_name), (
        f"expected the created ARN to match the one the role's condition names, got {created_arn!r}"
    )
    desc = sfn.describe_state_machine(stateMachineArn=created_arn)
    assert desc["status"] == "ACTIVE", f"expected status ACTIVE, got {desc['status']!r}"

    # Now that the matched twin proves general assumability already works, the mismatched role
    # must still be denied: a few more samples past that point are the permanence evidence.
    for _ in range(3):
        bad_results.append(_error(_try_create_bad))
        time.sleep(2)

    assert all(code == "AccessDeniedException" for code, _ in bad_results), (
        f"expected every sample to deny AccessDeniedException, got {bad_results!r}"
    )
    messages = {message for _, message in bad_results}
    assert messages == {_DENIAL_MESSAGE}, f"expected the single message {_DENIAL_MESSAGE!r}, got {messages!r}"

    assert not _lists_state_machine(sfn, bad_name), (
        f"expected {bad_name!r} absent from list_state_machines, found it present"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
