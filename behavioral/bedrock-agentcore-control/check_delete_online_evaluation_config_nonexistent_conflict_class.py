"""delete-online-evaluation-config-nonexistent-conflict-class."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-online-evaluation-config-nonexistent-conflict-class"
GROUP = "error-semantics"
SERVICES = ["bedrock-agentcore-control"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateOnlineEvaluationConfig with a name already in use answers ConflictException with the exact message and
    leaves the original intact; after delete, Get and a second delete answer ResourceNotFoundException "Online
    evaluation configuration not found", and the name can be created again."""
    client = ctx.client("bedrock-agentcore-control")
    role_arn = _create_role(ctx, "sim2realoecrole")
    log_group_name = ctx.unique_name("/sim2real/oecdup/")
    logs = ctx.client("logs")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: _best_effort_delete_log_group(logs, log_group_name))

    data_source_config = {
        "cloudWatchLogs": {
            "serviceNames": ["sim2real-test-service"],
            "logGroupNames": [log_group_name],
        }
    }
    rule = {"samplingConfig": {"samplingPercentage": 10.0}}

    name = _alnum_name(ctx, "sim2realOecDup")
    first = _retry_role_propagation(
        lambda: client.create_online_evaluation_config(
            onlineEvaluationConfigName=name,
            rule=rule,
            dataSourceConfig=data_source_config,
            insights=[{"insightId": "Builtin.Insight.UserIntent"}],
            evaluationExecutionRoleArn=role_arn,
            enableOnCreate=False,
            tags={"sim2real": CHECK},
        )
    )
    first_id = first["onlineEvaluationConfigId"]
    ctx.on_cleanup(lambda: _best_effort_delete(client, first_id))

    code, message = _error_detail(
        lambda: client.create_online_evaluation_config(
            onlineEvaluationConfigName=name,
            rule=rule,
            dataSourceConfig=data_source_config,
            insights=[{"insightId": "Builtin.Insight.UserIntent"}],
            evaluationExecutionRoleArn=role_arn,
            enableOnCreate=False,
        )
    )
    assert code == "ConflictException", f"expected ConflictException, got {code}"
    expected_message = "Online evaluation configuration with same name already exists"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: still exactly the original config under that name/id.
    got = client.get_online_evaluation_config(onlineEvaluationConfigId=first_id)
    assert got["onlineEvaluationConfigName"] == name, (
        f"expected original config name {name!r} unchanged, got {got['onlineEvaluationConfigName']!r}"
    )

    # Delete the original (exercises DeleteOnlineEvaluationConfig) and wait for it to
    # actually be gone.
    client.delete_online_evaluation_config(onlineEvaluationConfigId=first_id)
    gone_code, gone_message = _poll_gone(
        lambda: client.get_online_evaluation_config(onlineEvaluationConfigId=first_id), timeout_s=60.0
    )
    assert gone_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {gone_code}"
    expected_gone_message = "Online evaluation configuration not found"
    assert gone_message == expected_gone_message, f"expected message {expected_gone_message!r}, got {gone_message!r}"

    # A mutation on the now-dead id must also classify as not-found: DeleteOnlineEvaluationConfig
    # models ConflictException too, so this proves the two error classes are not confused on an
    # already-deleted id.
    redelete_code, redelete_message = _error_detail(lambda: client.delete_online_evaluation_config(onlineEvaluationConfigId=first_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException re-deleting a gone config, got {redelete_code}"
    )
    expected_redelete_message = "Online evaluation configuration not found"
    assert redelete_message == expected_redelete_message, f"expected message {expected_redelete_message!r}, got {redelete_message!r}"

    # Positive control: the name is now free and creating with it again succeeds.
    second = _retry_role_propagation(
        lambda: client.create_online_evaluation_config(
            onlineEvaluationConfigName=name,
            rule=rule,
            dataSourceConfig=data_source_config,
            insights=[{"insightId": "Builtin.Insight.UserIntent"}],
            evaluationExecutionRoleArn=role_arn,
            enableOnCreate=False,
            tags={"sim2real": CHECK},
        )
    )
    ctx.on_cleanup(lambda: _best_effort_delete(client, second["onlineEvaluationConfigId"]))
    got2 = client.get_online_evaluation_config(onlineEvaluationConfigId=second["onlineEvaluationConfigId"])
    assert got2["onlineEvaluationConfigName"] == name, (
        f"expected reused name {name!r} on the new config, got {got2['onlineEvaluationConfigName']!r}"
    )


def _error_detail(fn):
    """Return (code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _alnum_name(ctx, prefix: str) -> str:
    raw = ctx.unique_name(prefix)
    return "".join(ch for ch in raw if ch.isalnum() or ch == "_")


def _create_role(ctx, prefix: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name(f"sim2real-behav-{prefix}-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "bedrock-agentcore.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = resp["Role"]["Arn"]
    ctx.on_cleanup(lambda: _best_effort_delete_role(iam, role_name))
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


def _best_effort_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _best_effort_delete_log_group(logs, log_group_name: str) -> None:
    try:
        logs.delete_log_group(logGroupName=log_group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
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


def _poll_gone(read, timeout_s=120.0, interval_s=3.0):
    """Poll read() until it raises ClientError; return (code, message). Raise on timeout."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = read()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"resource still readable after {timeout_s}s; last value={last!r}")


def _best_effort_delete(client, config_id: str) -> None:
    try:
        client.delete_online_evaluation_config(onlineEvaluationConfigId=config_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

