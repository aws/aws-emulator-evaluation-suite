"""lambda-sdk-iot-publish-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-sdk-iot-publish-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["iot", "lambda"]


@tags("axis:negative-delivery", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A handler whose role lacks iot:Publish gets ForbiddenException from iot-data publish and nothing reaches
    the rule's SQS queue, while a sibling function with iot:Publish delivers its marker."""
    account_id = _account_id(ctx)
    queue = _create_queue(ctx)
    rule_role_arn = _create_rule_role(ctx, queue["arn"])
    topic = ctx.unique_name("sim2real/iot-lambda-pubneg/")
    rule_name = ctx.unique_name("sim2real_iotlam_pubneg_").replace("-", "_")
    _create_topic_rule(
        ctx,
        rule_name,
        sql=f"SELECT * FROM '{topic}'",
        actions=[{"sqs": {"roleArn": rule_role_arn, "queueUrl": queue["url"], "useBase64": False}}],
    )
    topic_arn = f"arn:aws:iot:{ctx.region}:{account_id}:topic/{topic}"

    denied_role_arn = _create_execution_role(
        ctx, [{"Effect": "Allow", "Action": "iot:DescribeEndpoint", "Resource": "*"}]
    )
    allowed_role_arn = _create_execution_role(
        ctx,
        [
            {"Effect": "Allow", "Action": "iot:DescribeEndpoint", "Resource": "*"},
            {"Effect": "Allow", "Action": "iot:Publish", "Resource": topic_arn},
        ],
    )
    fn_denied = _create_function(ctx, denied_role_arn, _HANDLER_SRC)
    fn_allowed = _create_function(ctx, allowed_role_arn, _HANDLER_SRC)

    # --- positive control first: measure THIS run's real forwarding latency on this pipe ---
    marker_allowed = ctx.unique_name("marker-allowed-")
    body_allowed = _invoke_until_delivered(
        ctx, fn_allowed, {"region": ctx.region, "topic": topic, "payload": json.dumps({"marker": marker_allowed})}
    )
    assert body_allowed == {"ok": True}, f"positive control lambda call failed: {body_allowed!r}"

    t_forward = time.monotonic()
    messages = _poll_until(
        lambda: _receive_all(ctx, queue["url"]),
        lambda msgs: any(m.get("marker") == marker_allowed for m in msgs),
        timeout_s=90.0,
        interval_s=3.0,
        description="positive-control publish forwarded to SQS via IoT rule",
    )
    forward_latency_s = time.monotonic() - t_forward
    matched = [m for m in messages if m.get("marker") == marker_allowed]
    assert matched == [{"marker": marker_allowed}], f"unexpected forwarded payload: {matched!r}"

    # --- break exactly one thing: the denied role has no iot:Publish ---
    marker_denied = ctx.unique_name("marker-denied-")
    body_denied = _invoke_until_stable(
        ctx, fn_denied, {"region": ctx.region, "topic": topic, "payload": json.dumps({"marker": marker_denied})}
    )
    assert body_denied.get("ok") is False, f"expected the unauthorized publish to fail, got {body_denied!r}"
    assert body_denied["error"] == "ForbiddenException", f"unexpected error code: {body_denied!r}"

    # Hold absence for >= 3x the latency this same pipe was just measured to need (floored so a
    # very fast pipe still gets a real window, capped to stay well inside the suite budget), and
    # require the absence to hold across multiple independent samples rather than a single wait.
    window_s = min(max(3.0 * forward_latency_s, 20.0), 90.0)
    deadline = time.monotonic() + window_s
    samples = 0
    while time.monotonic() < deadline:
        leaked = [m for m in _receive_all(ctx, queue["url"]) if m.get("marker") == marker_denied]
        assert leaked == [], f"denied publish must not have been delivered, but found: {leaked!r}"
        samples += 1
    assert samples >= 3, f"the absence window took too few samples to be meaningful: {samples}"


_ASSUME_ROLE_LAMBDA = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}

_HANDLER_SRC = (
    "import boto3\n"
    "from botocore.exceptions import ClientError\n\n"
    "def handler(event, context):\n"
    "    region = event['region']\n"
    "    try:\n"
    "        iot = boto3.client('iot', region_name=region)\n"
    "        ep = iot.describe_endpoint(endpointType='iot:Data-ATS')['endpointAddress']\n"
    "        data = boto3.client('iot-data', region_name=region, endpoint_url='https://' + ep)\n"
    "        data.publish(topic=event['topic'], qos=0, payload=event['payload'].encode('utf-8'))\n"
    "        return {'ok': True}\n"
    "    except ClientError as e:\n"
    "        return {'ok': False, 'error': e.response['Error']['Code'], 'message': str(e)}\n"
    "    except Exception as e:\n"
    "        # A transient network fault (e.g. EndpointConnectionError) is not a ClientError and\n"
    "        # must not crash the invocation as an opaque FunctionError: report it the same shape\n"
    "        # so the caller's retry loop can tell it apart from the permission decision under test.\n"
    "        return {'ok': False, 'error': type(e).__name__, 'message': str(e)}\n"
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
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-iotlam-q-"), tags={"sim2real-check": CHECK})["QueueUrl"]
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
                Tags={"sim2real-check": CHECK},
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


def _invoke(ctx, fn_name: str, payload: dict[str, Any]) -> dict[str, Any]:
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=fn_name, Payload=json.dumps(payload).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation failed ({resp['FunctionError']}): {body!r}")
    return body


def _invoke_until_delivered(ctx, fn_name: str, payload: dict[str, Any], timeout_s: float = 60.0) -> dict[str, Any]:
    """Absorbs IAM role-propagation lag on a freshly attached allow policy."""
    deadline = time.monotonic() + timeout_s
    last_body: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last_body = _invoke(ctx, fn_name, payload)
        if last_body.get("ok"):
            return last_body
        time.sleep(4.0)
    return last_body


def _invoke_until_stable(ctx, fn_name: str, payload: dict[str, Any], attempts: int = 3) -> dict[str, Any]:
    """The denied role has no allow statement to propagate, so a handful of
    fixed retries is enough to rule out a purely transient error before we
    treat the rejection as the steady-state result."""
    last_body: dict[str, Any] = {}
    for _ in range(attempts):
        last_body = _invoke(ctx, fn_name, payload)
        if last_body.get("error") == "ForbiddenException":
            return last_body
        time.sleep(2.0)
    return last_body


def _create_topic_rule(ctx, rule_name: str, sql: str, actions: list[dict[str, Any]]) -> None:
    iot = ctx.client("iot")
    payload = {"sql": sql, "awsIotSqlVersion": "2016-03-23", "actions": actions, "ruleDisabled": False}

    def _try_create():
        try:
            iot.create_topic_rule(ruleName=rule_name, topicRulePayload=payload, tags=f"sim2real-check={CHECK}")
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
