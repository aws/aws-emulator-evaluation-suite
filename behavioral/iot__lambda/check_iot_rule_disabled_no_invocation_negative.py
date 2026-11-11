"""iot-rule-disabled-no-invocation-negative."""
from __future__ import annotations

import io
import json
import time
import uuid
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "iot-rule-disabled-no-invocation-negative"
GROUP = "permission-boundary"
SERVICES = ["iot", "lambda"]


@tags("axis:negative-delivery", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A disabled topic rule (ruleDisabled=True) never invokes its Lambda on a matching publish, while an
    identically wired enabled sibling rule invokes it."""
    queue_url = _create_queue(ctx)
    func_name, func_arn = _create_forwarding_function(ctx, queue_url)

    topic_enabled = ctx.unique_name("sim2real-iotlam-enabled-")
    rule_enabled_name = _rule_name(ctx, "enabled")
    rule_enabled_arn = _create_topic_rule(
        ctx,
        rule_enabled_name,
        sql=f"SELECT * FROM '{topic_enabled}'",
        actions=[{"lambda": {"functionArn": func_arn}}],
        enabled=True,
    )
    _add_lambda_permission(ctx, func_name, rule_enabled_arn, "enabled")

    topic_disabled = ctx.unique_name("sim2real-iotlam-disabled-")
    rule_disabled_name = _rule_name(ctx, "disabled")
    rule_disabled_arn = _create_topic_rule(
        ctx,
        rule_disabled_name,
        sql=f"SELECT * FROM '{topic_disabled}'",
        actions=[{"lambda": {"functionArn": func_arn}}],
        enabled=False,
    )
    _add_lambda_permission(ctx, func_name, rule_disabled_arn, "disabled")

    marker_enabled = str(uuid.uuid4())
    marker_disabled = str(uuid.uuid4())
    _publish(ctx, topic_enabled, {"marker": marker_enabled})
    _publish(ctx, topic_disabled, {"marker": marker_disabled})

    messages = _wait_for_message(ctx, queue_url, lambda m: m.get("marker") == marker_enabled, timeout_s=90)
    extra = _collect_for(ctx, queue_url, duration_s=25.0)
    all_seen = messages + extra
    assert any(m.get("marker") == marker_enabled for m in all_seen), "positive control did not invoke the function"
    assert not any(m.get("marker") == marker_disabled for m in all_seen), (
        "a disabled topic rule still invoked the Lambda action"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_for_effect(probe, predicate, timeout_s=120.0, interval_s=2.0, description="effect"):
    """Poll for an async cross-service effect (default 120s)."""
    return _poll_until(probe, predicate, timeout_s=timeout_s, interval_s=interval_s, description=description)


def _retry_on_role_propagation(fn, retry_codes, timeout_s=45.0, interval_s=3.0, description="operation"):
    """Retry fn() while it fails with an IAM-role-propagation-flavored error code."""

    def probe():
        try:
            return ("ok", fn())
        except ClientError as exc:
            if exc.response["Error"]["Code"] in retry_codes:
                return ("retry", None)
            raise

    _, result = _poll_until(
        probe, lambda r: r[0] == "ok", timeout_s=timeout_s, interval_s=interval_s, description=description
    )
    return result


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _iot_data_client(ctx):
    iot = ctx.client("iot")
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    return ctx.client("iot-data", endpoint_url=ctx.endpoint_url(endpoint))


_FORWARD_LAMBDA_CODE = """
import json
import os
import boto3

_sqs = boto3.client("sqs")


def handler(event, context):
    _sqs.send_message(
        QueueUrl=os.environ["FORWARD_QUEUE_URL"],
        MessageBody=json.dumps(event, default=str),
    )
    return {"forwarded": True}
"""


def _zip_bytes(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iotlam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sqs-send",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sqs-send"))
    return role_arn


def _create_forwarding_function(ctx, queue_url: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    role_arn = _create_lambda_role(ctx)
    func_name = ctx.unique_name("sim2real-iotlam-fwd-")
    zip_bytes = _zip_bytes(_FORWARD_LAMBDA_CODE)
    ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
    fn = _retry_on_role_propagation(
        lambda: lam.create_function(
            FunctionName=func_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Environment={"Variables": {"FORWARD_QUEUE_URL": queue_url}},
            Timeout=30,
            Tags={"sim2real": CHECK},
        ),
        retry_codes={"InvalidParameterValueException"},
        description=f"lambda function {func_name} create (role propagation)",
    )
    func_arn = fn["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=func_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=func_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {func_name} Active",
    )
    return func_name, func_arn


def _create_queue(ctx) -> str:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-iotlam-q-"), tags={"sim2real": CHECK}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return url


def _rule_name(ctx, kind: str) -> str:
    raw = ctx.unique_name(f"sim2real_iotlam_{kind}_")
    return "".join(c if (c.isalnum() or c == "_") else "_" for c in raw)


def _create_topic_rule(
    ctx, rule_name: str, sql: str, actions: list[dict], error_action: dict | None = None, enabled: bool = True
) -> str:
    iot = ctx.client("iot")
    payload: dict[str, Any] = {
        "sql": sql,
        "awsIotSqlVersion": "2016-03-23",
        "actions": actions,
        "ruleDisabled": not enabled,
    }
    if error_action is not None:
        payload["errorAction"] = error_action
    _retry_on_role_propagation(
        lambda: iot.create_topic_rule(
            ruleName=rule_name, topicRulePayload=payload, tags=f"sim2real={CHECK}"
        ),
        retry_codes={"InvalidRequestException"},
        description=f"topic rule {rule_name} create (role propagation)",
    )
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_name))
    return f"arn:aws:iot:{ctx.region}:{_account_id(ctx)}:rule/{rule_name}"


def _add_lambda_permission(ctx, function_name: str, source_arn: str, sid_hint: str) -> None:
    lam = ctx.client("lambda")
    sid = ctx.unique_name(f"sim2real-iotlam-perm-{sid_hint}-")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=sid,
        Action="lambda:InvokeFunction",
        Principal="iot.amazonaws.com",
        SourceArn=source_arn,
    )
    ctx.on_cleanup(lambda: lam.remove_permission(FunctionName=function_name, StatementId=sid))


def _publish(ctx, topic: str, payload: dict) -> None:
    data = _iot_data_client(ctx)
    data.publish(topic=topic, qos=1, payload=json.dumps(payload).encode("utf-8"))


def _receive_once(ctx, queue_url: str, wait_s: int = 5) -> list[dict]:
    sqs = ctx.client("sqs")
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s)
    out = []
    for m in resp.get("Messages", []):
        try:
            out.append(json.loads(m["Body"]))
        except (ValueError, TypeError):
            out.append({"_raw": m["Body"]})
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
    return out


def _wait_for_message(ctx, queue_url: str, predicate, timeout_s: float = 90.0) -> list[dict]:
    collected: list[dict] = []

    def probe():
        collected.extend(_receive_once(ctx, queue_url, wait_s=5))
        return collected

    _wait_for_effect(
        probe,
        lambda msgs: any(predicate(m) for m in msgs),
        timeout_s=timeout_s,
        interval_s=1.0,
        description="matching queue message",
    )
    return collected


def _collect_for(ctx, queue_url: str, duration_s: float = 40.0) -> list[dict]:
    deadline = time.monotonic() + duration_s
    out: list[dict] = []
    while time.monotonic() < deadline:
        out.extend(_receive_once(ctx, queue_url, wait_s=5))
    return out


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
