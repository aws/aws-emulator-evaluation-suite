"""iot-rule-lambda-payload-data-format."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iot-rule-lambda-payload-data-format"
GROUP = "data-format"
SERVICES = ["iot", "lambda"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """The SQL SELECT statement in the topic rule transforms the raw MQTT JSON
    payload into the exact JSON event structure delivered to Lambda: computed
    fields, aliases and the topic() function are all reflected faithfully."""
    account_id = _account_id(ctx)
    queue = _create_queue(ctx)
    role_arn = _create_forwarder_role(ctx, queue["arn"])
    fn = _create_forwarder_function(ctx, role_arn, queue["url"])

    rule_name = ctx.unique_name("sim2real_iot_fmt_").replace("-", "_")
    topic = ctx.unique_name("sim2real/iot-lambda-fmt/")
    rule_arn = f"arn:aws:iot:{ctx.region}:{account_id}:rule/{rule_name}"
    _allow_iot_invoke(ctx, fn["name"], rule_arn, account_id)
    sql = (
        f"SELECT temperature * 9 / 5 + 32 AS temperatureF, humidity AS humidityPct, "
        f"topic() AS sourceTopic FROM '{topic}'"
    )
    _create_topic_rule(ctx, rule_name, sql=sql, actions=[{"lambda": {"functionArn": fn["arn"]}}])

    iot_data = _iot_data_client(ctx)
    payload = {"temperature": 20, "humidity": 55, "extraField": "ignored-by-select"}
    messages = _publish_until_delivered(
        ctx, iot_data, topic, json.dumps(payload).encode(), queue["url"]
    )
    assert messages, "expected the transformed event to be forwarded to SQS"
    event = messages[0]
    assert set(event.keys()) == {"temperatureF", "humidityPct", "sourceTopic"}, event
    assert abs(float(event["temperatureF"]) - 68.0) < 0.01, event
    assert event["humidityPct"] == 55, event
    assert event["sourceTopic"] == topic, event


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


_ASSUME_ROLE_LAMBDA = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

_FORWARDER_CODE = (
    "import json\nimport os\nimport boto3\n\nsqs = boto3.client('sqs')\n\n"
    "def handler(event, context):\n"
    "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(event))\n"
    "    return {'ok': True}\n"
)


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_forwarder_role(ctx, queue_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iotlam-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ASSUME_ROLE_LAMBDA),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sqs-send",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sqs-send"))
    return role_arn


def _create_forwarder_function(ctx, role_arn: str, queue_url: str) -> dict[str, str]:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-iot-fwd-")
    zip_bytes = _zip_bytes(_FORWARDER_CODE)

    def _try_create():
        try:
            return lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": {"QUEUE_URL": queue_url}},
                Tags={"sim2real:managed": "true"},
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    resp = _poll_until(
        _try_create,
        lambda r: r is not None,
        timeout_s=60,
        interval_s=3.0,
        description=f"function {fn_name} create (role propagation)",
    )
    fn_arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    ctx.on_cleanup(
        lambda: ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{fn_name}")
    )
    _poll_until(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {fn_name} Active",
    )
    return {"name": fn_name, "arn": fn_arn}


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-iot-q-"), tags={"sim2real:managed": "true"}
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _iot_data_client(ctx):
    iot = ctx.client("iot")
    addr = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    url = ctx.endpoint_url(addr)
    client = ctx.client("iot-data", endpoint_url=url)
    _wait_for_iot_data_ready(client)
    return client


def _wait_for_iot_data_ready(iot_data, timeout_s=180.0, interval_s=5.0):
    """The per-account IoT data-ATS endpoint can take a short time to become
    reachable (DNS/cert propagation) right after being (re)provisioned; retry a
    harmless publish until the endpoint answers without a connectivity/SNI
    error, so real test publishes below don't spuriously observe "no delivery"."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            iot_data.publish(topic="sim2real/warmup/probe", qos=0, payload=b"{}")
            return
        except Exception as e:  # noqa: BLE001 - any transient error, keep retrying
            last_exc = e
            time.sleep(interval_s)
    raise AssertionError(f"iot-data endpoint never became reachable: {last_exc!r}")


def _allow_iot_invoke(ctx, function_name: str, rule_arn: str, account_id: str) -> None:
    lam = ctx.client("lambda")
    stmt_id = ctx.unique_name("sim2real-iot-invoke-")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=stmt_id,
        Action="lambda:InvokeFunction",
        Principal="iot.amazonaws.com",
        SourceArn=rule_arn,
        SourceAccount=account_id,
    )
    ctx.on_cleanup(lambda: lam.remove_permission(FunctionName=function_name, StatementId=stmt_id))


def _create_topic_rule(ctx, rule_name, sql, actions, error_action=None, rule_disabled=False) -> None:
    iot = ctx.client("iot")
    payload: dict[str, Any] = {
        "sql": sql,
        "awsIotSqlVersion": "2016-03-23",
        "actions": actions,
        "ruleDisabled": rule_disabled,
    }
    if error_action:
        payload["errorAction"] = error_action
    iot.create_topic_rule(ruleName=rule_name, topicRulePayload=payload)
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_name))


def _receive_all(ctx, queue_url: str, max_messages: int = 10):
    sqs = ctx.client("sqs")
    out = []
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=5)
    for msg in resp.get("Messages", []):
        try:
            body = json.loads(msg["Body"])
        except (json.JSONDecodeError, ValueError):
            body = msg["Body"]
        out.append(body)
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return out


def _publish_until_delivered(
    ctx, iot_data, topic: str, payload_bytes: bytes, queue_url: str, timeout_s=90.0, interval_s=8.0
):
    """Republishing periodically absorbs IAM role-propagation lag on the first
    few attempts while polling SQS for the resulting observable effect. Publish
    itself is retried on transient connectivity errors (endpoint warm-up)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            iot_data.publish(topic=topic, qos=1, payload=payload_bytes)
        except Exception:
            time.sleep(2.0)
            continue
        sub_deadline = time.monotonic() + interval_s
        while time.monotonic() < sub_deadline:
            msgs = _receive_all(ctx, queue_url)
            if msgs:
                return msgs
            time.sleep(1.5)
    return []



if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
