"""put-model-invocation-logging-config-enforced-on-invoke."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "put-model-invocation-logging-config-enforced-on-invoke"
GROUP = "server-side"
SERVICES = ["bedrock"]

_MODEL_ID = "moonshotai.kimi-k2.5"


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "resource:account-singleton:bedrock-invocation-logging")
def run(ctx) -> None:
    """After PutModelInvocationLoggingConfiguration, an InvokeModel call with no per-call logging
    option is logged to the configured CloudWatch Logs group with the marker and modelId."""
    # InvokeModel is real, billed inference and needs model access granted to the account.
    bedrock = ctx.client("bedrock")
    logs = ctx.client("logs")
    ctx.client("iam")

    log_group_name = ctx.unique_name("/sim2real/bedrock-logging-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": "bedrock-invocation-logging"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = logs.describe_log_groups(logGroupNamePrefix=log_group_name)[
        "logGroups"
    ][0]["arn"]

    role_arn = _create_bedrock_logging_role(ctx, log_group_arn)

    original = bedrock.get_model_invocation_logging_configuration()
    original_config = original.get("loggingConfig")

    def _restore() -> None:
        if original_config:
            bedrock.put_model_invocation_logging_configuration(loggingConfig=original_config)
        else:
            bedrock.delete_model_invocation_logging_configuration()

    ctx.on_cleanup(_restore)

    _put_logging_config_with_role_propagation_retry(
        bedrock,
        {
            "cloudWatchConfig": {"logGroupName": log_group_name, "roleArn": role_arn},
            "textDataDeliveryEnabled": True,
        },
    )
    fetched = bedrock.get_model_invocation_logging_configuration()["loggingConfig"]
    assert fetched["cloudWatchConfig"]["logGroupName"] == log_group_name, (
        f"expected Get to reflect the log group just configured {log_group_name!r}; got {fetched!r}"
    )

    marker = f"sim2real-marker-{uuid.uuid4().hex[:12]}"
    bedrock_runtime = ctx.client("bedrock-runtime")
    body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 8,
            "messages": [{"role": "user", "content": f"Repeat back the token {marker}."}],
        }
    )
    try:
        bedrock_runtime.invoke_model(
            modelId=_MODEL_ID, contentType="application/json", accept="application/json", body=body
        )
    except Exception as err:  # noqa: BLE001
        code = getattr(err, "response", {}).get("Error", {}).get("Code") if hasattr(err, "response") else None
        if code == "AccessDeniedException":
            raise AssertionError(
                f"model access not granted for {_MODEL_ID} in this account/region; "
                "request access via the Bedrock console model-access page"
            ) from err
        raise

    found = _poll_until(
        lambda: _collect_log_messages(logs, log_group_name),
        lambda messages: any(marker in m for m in messages),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert any(marker in m and _MODEL_ID in m for m in found), (
        "expected the server-side logging config (set with no client-side logging "
        "opt-in on the InvokeModel call) to deliver an invocation log entry "
        f"containing both the marker and modelId; got messages={found!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _put_logging_config_with_role_propagation_retry(bedrock, logging_config, timeout_s=60.0, interval_s=5.0):
    """Retry Put while Bedrock answers ValidationException because the just-created role's
    log-group permissions have not yet propagated through IAM."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            bedrock.put_model_invocation_logging_configuration(loggingConfig=logging_config)
            return
        except ClientError as err:
            msg = err.response.get("Error", {}).get("Message", "")
            if "Failed to validate permissions" in msg and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _collect_log_messages(logs_client, log_group_name):
    messages = []
    try:
        resp = logs_client.filter_log_events(logGroupName=log_group_name)
    except logs_client.exceptions.ResourceNotFoundException:
        return messages
    for event in resp.get("events", []):
        messages.append(event.get("message", ""))
    return messages


def _create_bedrock_logging_role(ctx, log_group_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bedlog-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "bedrock.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "bedrock-invocation-logging"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "logging"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
                "Resource": [log_group_arn, f"{log_group_arn}:*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
