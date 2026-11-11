"""online-evaluation-config-lifecycle-transitions."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "online-evaluation-config-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """OnlineEvaluationConfig create->update(disable)->delete; stops post-delete."""
    client = ctx.client("bedrock-agentcore-control")
    logs = ctx.client("logs")
    role_arn = _create_role(ctx, "bedrock-agentcore.amazonaws.com", "sim2reals3oec")

    log_group_name = ctx.unique_name("/sim2real/oec/")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))

    config_name = _alnum_name(ctx, "sim2realOec")
    created = _retry_role_propagation(
        lambda: client.create_online_evaluation_config(
            onlineEvaluationConfigName=config_name,
            rule={"samplingConfig": {"samplingPercentage": 10.0}},
            dataSourceConfig={
                "cloudWatchLogs": {
                    "logGroupNames": [log_group_name],
                    "serviceNames": ["sim2real-test-service"],
                }
            },
            insights=[{"insightId": "Builtin.Insight.UserIntent"}],
            evaluationExecutionRoleArn=role_arn,
            enableOnCreate=True,
            tags={"sim2real": CHECK},
        )
    )
    config_id = created["onlineEvaluationConfigId"]
    ctx.on_cleanup(lambda: _delete_ignore_not_found(client, config_id))
    assert created["executionStatus"] == "ENABLED", (
        f"expected CreateOnlineEvaluationConfig with enableOnCreate=True to return executionStatus "
        f"ENABLED, got {created['executionStatus']!r}"
    )

    active = _poll_until(
        lambda: client.get_online_evaluation_config(onlineEvaluationConfigId=config_id),
        lambda r: r["status"] == "ACTIVE",
        timeout_s=180.0,
    )
    assert active["executionStatus"] == "ENABLED", (
        f"expected executionStatus ENABLED once status reached ACTIVE, got {active['executionStatus']!r}"
    )

    client.update_online_evaluation_config(onlineEvaluationConfigId=config_id, executionStatus="DISABLED")
    disabled = _poll_until(
        lambda: client.get_online_evaluation_config(onlineEvaluationConfigId=config_id),
        lambda r: r["executionStatus"] == "DISABLED",
        timeout_s=180.0,
    )
    assert disabled["executionStatus"] == "DISABLED", (
        f"expected UpdateOnlineEvaluationConfig(executionStatus=DISABLED) to converge to DISABLED, "
        f"got {disabled['executionStatus']!r}"
    )

    client.delete_online_evaluation_config(onlineEvaluationConfigId=config_id)

    final_code, final_message = _error(
        lambda: client.get_online_evaluation_config(onlineEvaluationConfigId=config_id),
        until_code="ResourceNotFoundException",
        timeout_s=180.0,
    )
    assert final_code == "ResourceNotFoundException", (
        f"expected GetOnlineEvaluationConfig on a deleted config to raise ResourceNotFoundException, "
        f"got {final_code!r}"
    )
    expected = "Online evaluation configuration not found"
    assert final_message == expected, f"expected message {expected!r}, got {final_message!r}"

    delete_again_code, delete_again_message = _error(
        lambda: client.delete_online_evaluation_config(onlineEvaluationConfigId=config_id)
    )
    assert delete_again_code == "ResourceNotFoundException", (
        f"expected DeleteOnlineEvaluationConfig on an already-deleted config to raise "
        f"ResourceNotFoundException (proving the id is dead, not just absent from Get), "
        f"got {delete_again_code!r}"
    )
    expected = "Online evaluation configuration not found"
    assert delete_again_message == expected, (
        f"expected message {expected!r}, got {delete_again_message!r}"
    )


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "_")


def _create_role(ctx, principal: str, prefix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(prefix)[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sim2real-online-eval-permissions",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "CloudWatchLogReadStatement",
                        "Effect": "Allow",
                        "Action": ["logs:DescribeLogGroups", "logs:GetQueryResults", "logs:StartQuery"],
                        "Resource": "*",
                    },
                    {
                        "Sid": "CloudWatchLogWriteStatement",
                        "Effect": "Allow",
                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": "arn:aws:logs:*:*:log-group:/aws/bedrock-agentcore/evaluations/*",
                    },
                    {
                        "Sid": "CloudWatchIndexPolicyStatement",
                        "Effect": "Allow",
                        "Action": ["logs:DescribeIndexPolicies", "logs:PutIndexPolicy"],
                        "Resource": ["arn:aws:logs:*:*:log-group:aws/spans", "arn:aws:logs:*:*:log-group:aws/spans:*"],
                    },
                    {
                        "Sid": "BedrockInvokeStatement",
                        "Effect": "Allow",
                        "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
                        "Resource": ["arn:aws:bedrock:*::foundation-model/*", "arn:aws:bedrock:*:*:inference-profile/*"],
                    },
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: _delete_role_policy_ignore(iam, role_name, "sim2real-online-eval-permissions"))
    return arn


def _delete_role_policy_ignore(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _retry_role_propagation(fn, timeout_s=60.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and (
                "assum" in message.lower() or "permission" in message.lower()
            ):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise last_err


def _error(fn, *, until_code=None, timeout_s=0.0, interval_s=3.0):
    """Return (code, message) of the ClientError fn() raises. With until_code, retry while fn()
    succeeds or raises another code, for up to timeout_s. A call that never fails raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            error = err.response["Error"]
            if until_code is None or error["Code"] == until_code or time.monotonic() >= deadline:
                return error["Code"], error.get("Message", "")
        else:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"expected a ClientError, but the call succeeded and returned {result!r}"
                )
        time.sleep(interval_s)


def _delete_ignore_not_found(client, config_id: str) -> None:
    try:
        client.delete_online_evaluation_config(onlineEvaluationConfigId=config_id)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("ResourceNotFoundException", "ConflictException"):
            raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
