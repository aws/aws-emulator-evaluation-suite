"""model-invocation-log-event-shape-at-cloudwatch-logs."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "model-invocation-log-event-shape-at-cloudwatch-logs"
GROUP = "observability"
SERVICES = ["bedrock", "logs"]

MODEL_ID = "amazon.nova-lite-v1:0"
_PROPAGATION_TIMEOUT_S = 60.0
_DELIVERY_TIMEOUT_S = 240.0


def _current_config(bc):
    try:
        return bc.get_model_invocation_logging_configuration().get("loggingConfig")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
        return None


def _restore_logging(bc, prior):
    if prior is None:
        bc.delete_model_invocation_logging_configuration()
    else:
        bc.put_model_invocation_logging_configuration(loggingConfig=prior)


def _create_logging_role(ctx, log_group_arn):
    """A role Bedrock assumes to write into exactly this log group."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-bedlog-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "bedrock.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "bedrock-invocation-logging-cwl"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
            "Resource": [log_group_arn, f"{log_group_arn}:*"],
        }],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="logging", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="logging"))
    return role["Role"]["Arn"]


def _put_with_role_propagation(bc, logging_config, timeout_s):
    """Put `logging_config`, retrying only while Bedrock answers "Failed to validate permissions"
    because the just-created role has not yet propagated through IAM."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            bc.put_model_invocation_logging_configuration(loggingConfig=logging_config)
            return
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if "Failed to validate permissions" in msg and time.monotonic() < deadline:
                time.sleep(2.0)
                continue
            raise


def _log_records(logs, log_group_name):
    """Every JSON invocation record delivered to the log group so far."""
    records = []
    for page in logs.get_paginator("filter_log_events").paginate(logGroupName=log_group_name):
        for event in page.get("events", []):
            try:
                records.append(json.loads(event.get("message", "")))
            except ValueError:
                continue
    return records


@tags(
    "axis:happy-path",
    "dp:api",
    "plane:control",
    "plane:data",
    "cap:c1", "resource:account-singleton:bedrock-invocation-logging",
)
def run(ctx) -> None:
    """With a CloudWatch Logs destination, a Converse call is delivered as a JSON log event with
    schemaType ModelInvocationLog, operation Converse, the modelId, accountId and region, the prompt
    in inputBodyJson and token counts equal to the usage the Converse response reported."""
    bc = ctx.client("bedrock")
    logs = ctx.client("logs")
    rt = ctx.client("bedrock-runtime")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # ACCOUNT-and-region-level singleton: stash and register the restore before anything can fail.
    prior = _current_config(bc)
    ctx.on_cleanup(lambda: _restore_logging(bc, prior))

    log_group_name = ctx.unique_name("/sim2real/bedrock-invlog-cwl-")
    logs.create_log_group(
        logGroupName=log_group_name, tags={"sim2real": "bedrock-invocation-logging-cwl"}
    )
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    groups = logs.describe_log_groups(logGroupNamePrefix=log_group_name)["logGroups"]
    assert len(groups) == 1, (
        f"exactly one log group must match the unique prefix {log_group_name!r}; got {groups!r}"
    )
    role_arn = _create_logging_role(ctx, groups[0]["arn"])

    _put_with_role_propagation(bc, {
        "cloudWatchConfig": {"logGroupName": log_group_name, "roleArn": role_arn},
        "textDataDeliveryEnabled": True,
        "imageDataDeliveryEnabled": False,
        "embeddingDataDeliveryEnabled": False,
    }, _PROPAGATION_TIMEOUT_S)
    live = bc.get_model_invocation_logging_configuration()["loggingConfig"]
    assert live["cloudWatchConfig"]["logGroupName"] == log_group_name, (
        f"the configuration must name the log group just created; got {live!r}"
    )

    nonce = "sim2realnonce" + uuid.uuid4().hex[:12]
    response = rt.converse(
        modelId=MODEL_ID,
        messages=[{"role": "user", "content": [{
            "text": f"Repeat exactly this token and nothing else: {nonce}"}]}],
        inferenceConfig={"maxTokens": 40, "temperature": 0.0},
    )

    # Bounded poll for the record carrying THIS nonce; other invocations can share the group.
    deadline = time.monotonic() + _DELIVERY_TIMEOUT_S
    matched = None
    while matched is None:
        matched = next(
            (r for r in _log_records(logs, log_group_name) if nonce in json.dumps(r.get("input", {}))),
            None,
        )
        if matched is None:
            assert time.monotonic() < deadline, (
                f"no invocation log event carrying the prompt nonce {nonce!r} reached "
                f"{log_group_name} within {_DELIVERY_TIMEOUT_S}s"
            )
            time.sleep(2)

    assert matched.get("schemaType") == "ModelInvocationLog", matched.get("schemaType")
    assert matched.get("operation") == "Converse", matched.get("operation")
    assert matched.get("modelId") == MODEL_ID, matched.get("modelId")
    assert matched.get("accountId") == account, matched.get("accountId")
    assert matched.get("region") == ctx.region, matched.get("region")
    prompt_text = matched["input"]["inputBodyJson"]["messages"][0]["content"][0]["text"]
    assert nonce in prompt_text, f"the logged prompt must contain the nonce verbatim; got {prompt_text!r}"
    assert matched["input"]["inputTokenCount"] == response["usage"]["inputTokens"], (
        f"inputTokenCount {matched['input']['inputTokenCount']!r} != usage {response['usage']!r}"
    )
    assert matched["output"]["outputTokenCount"] == response["usage"]["outputTokens"], (
        f"outputTokenCount {matched['output']['outputTokenCount']!r} != usage {response['usage']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
