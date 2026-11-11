"""lambda-sdk-iot-publish-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-iot-publish-positive"
GROUP = "sdk-call"
SERVICES = ["iot", "lambda"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A message a Lambda function publishes with the iot-data client reaches an IoT topic rule, which forwards
    exactly that marker to SQS."""
    account_id = _account_id(ctx)
    queue = _create_queue(ctx)
    rule_role_arn = _create_rule_role(ctx, queue["arn"])
    topic = ctx.unique_name("sim2real/iot-lambda-pub/")
    rule_name = ctx.unique_name("sim2real_iotlam_pub_").replace("-", "_")
    _create_topic_rule(
        ctx,
        rule_name,
        sql=f"SELECT * FROM '{topic}'",
        actions=[{"sqs": {"roleArn": rule_role_arn, "queueUrl": queue["url"], "useBase64": False}}],
    )

    topic_arn = f"arn:aws:iot:{ctx.region}:{account_id}:topic/{topic}"
    lambda_role_arn = _create_execution_role(
        ctx,
        [
            {"Effect": "Allow", "Action": "iot:DescribeEndpoint", "Resource": "*"},
            {"Effect": "Allow", "Action": "iot:Publish", "Resource": topic_arn},
        ],
    )
    fn_name = _create_function(ctx, lambda_role_arn, _HANDLER_SRC)

    marker = ctx.unique_name("marker-")
    body = _invoke_until_delivered(
        ctx, fn_name, {"region": ctx.region, "topic": topic, "payload": json.dumps({"marker": marker})}
    )
    assert body == {"ok": True}, f"unexpected lambda response: {body!r}"

    messages = _poll_until(
        lambda: _receive_all(ctx, queue["url"]),
        lambda msgs: any(m.get("marker") == marker for m in msgs),
        timeout_s=90.0,
        interval_s=3.0,
        description="published message forwarded to SQS via IoT rule",
    )
    matched = [m for m in messages if m.get("marker") == marker]
    assert matched == [{"marker": marker}], f"unexpected forwarded payload: {matched!r}"


_ASSUME_ROLE_LAMBDA = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}

_HANDLER_SRC = (
    "import boto3\n\n"
    "def handler(event, context):\n"
    "    region = event['region']\n"
    "    iot = boto3.client('iot', region_name=region)\n"
    "    ep = iot.describe_endpoint(endpointType='iot:Data-ATS')['endpointAddress']\n"
    "    data = boto3.client('iot-data', region_name=region, endpoint_url='https://' + ep)\n"
    "    data.publish(topic=event['topic'], qos=0, payload=event['payload'].encode('utf-8'))\n"
    "    return {'ok': True}\n"
)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _zip_bytes(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_queue(ctx) -> dict[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-iotlam-q-"), tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    return {"url": url, "arn": arn}


def _create_rule_role(ctx, queue_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iotrule-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "iot.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sqs-send",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sqs-send"))
    return role_arn


def _create_execution_role(ctx, iot_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iotlam-role-")
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_ASSUME_ROLE_LAMBDA),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy))
    if iot_statements:
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="iot-access",
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": iot_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="iot-access"))
    return role_arn


def _create_function(ctx, role_arn: str, handler_src: str) -> str:
    lam = ctx.client("lambda")
    fn_name = ctx.unique_name("sim2real-iotlam-fn-")
    zip_bytes = _zip_bytes(handler_src)

    def _try_create():
        try:
            ctx.on_cleanup(lambda _n=fn_name: _delete_lambda_log_group(ctx, _n))
            return lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Tags={"sim2real": CHECK},
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    _poll_until(_try_create, lambda r: r is not None, timeout_s=60, interval_s=3.0, description=f"function {fn_name} create (role propagation)")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))
    _poll_until(
        lambda: lam.get_function(FunctionName=fn_name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"function {fn_name} Active",
    )
    return fn_name


def _invoke(ctx, fn_name: str, payload: dict[str, Any]) -> tuple[dict[str, Any], str | None]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    return body, resp.get("FunctionError")


def _invoke_until_delivered(ctx, fn_name: str, payload: dict[str, Any], timeout_s: float = 60.0) -> dict[str, Any]:
    """Absorbs IAM role-propagation lag on the execution role's freshly
    attached policy by retrying the whole invocation a few times. A FunctionError (the
    freshly-created function's attached policy or network path not yet live) is itself
    part of the lag being retried past, not a reason to give up on the first attempt."""
    deadline = time.monotonic() + timeout_s
    last_body: dict[str, Any] = {}
    last_error: str | None = None
    while time.monotonic() < deadline:
        last_body, last_error = _invoke(ctx, fn_name, payload)
        if not last_error and last_body.get("ok"):
            return last_body
        time.sleep(4.0)
    if last_error:
        raise AssertionError(
            f"lambda invocation still failing ({last_error}) after {timeout_s}s: {last_body!r}"
        )
    return last_body


def _create_topic_rule(ctx, rule_name: str, sql: str, actions: list[dict[str, Any]]) -> None:
    iot = ctx.client("iot")
    payload = {"sql": sql, "awsIotSqlVersion": "2016-03-23", "actions": actions, "ruleDisabled": False}

    def _try_create():
        try:
            iot.create_topic_rule(ruleName=rule_name, topicRulePayload=payload, tags=f"sim2real={CHECK}")
            return True
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidRequestException" and "unable to assume role" in str(e):
                return None
            raise

    _poll_until(_try_create, lambda r: r is not None, timeout_s=90, interval_s=5.0, description=f"topic rule {rule_name} create (role propagation)")
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_name))


def _receive_all(ctx, queue_url: str, max_messages: int = 10) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    out: list[dict[str, Any]] = []
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=max_messages, WaitTimeSeconds=5)
    for msg in resp.get("Messages", []):
        try:
            body = json.loads(msg["Body"])
        except (json.JSONDecodeError, ValueError):
            body = msg["Body"]
        out.append(body)
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
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
