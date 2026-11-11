"""lambda-iot-data-publish-missing-permission-negative."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "lambda-iot-data-publish-missing-permission-negative"
GROUP = "permission-boundary"
SERVICES = ["iot", "lambda"]

_HANDLER_CODE = """
import boto3
import json
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    client = boto3.client("iot-data", endpoint_url=event["endpoint_url"])
    try:
        client.publish(
            topic=event["topic"],
            qos=0,
            payload=json.dumps(event["message"]).encode("utf-8"),
        )
        return {"success": True}
    except ClientError as e:
        return {
            "success": False,
            "error_code": e.response["Error"]["Code"],
            "error_message": e.response["Error"].get("Message", ""),
        }
"""


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A handler whose role lacks iot:Publish has its iot-data publish refused with a bare ForbiddenException
    and nothing reaches the rule's SQS queue, while a role with the permission delivers the message."""
    iot = ctx.client("iot")
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    endpoint_url = ctx.endpoint_url(endpoint)

    topic = ctx.unique_name("sim2real/iotlam/pubneg/")
    queue_url, queue_arn = _create_queue(ctx)
    _create_topic_rule_to_sqs(ctx, topic, queue_url, queue_arn)

    # --- negative: role has only basic Lambda logging permissions, no IoT actions ---
    denied_role_arn = _create_lambda_role(ctx, None)
    denied_fn = _create_function(ctx, denied_role_arn, _HANDLER_CODE)

    denied_message = {"marker": ctx.unique_name("denied-")}
    denied_payload = _invoke_json(
        ctx, denied_fn, {"endpoint_url": endpoint_url, "topic": topic, "message": denied_message}
    )
    assert denied_payload["success"] is False, (
        f"expected the unauthorized publish to fail, got {denied_payload!r}"
    )
    denied_code = denied_payload["error_code"]
    denied_msg = denied_payload.get("error_message", "")
    # The data plane refuses with a bare 403 that carries no message.
    assert (denied_code, denied_msg) == ("ForbiddenException", None), (
        f"unexpected error for missing IAM permission: code={denied_code!r} message={denied_msg!r}"
    )

    assert _drained_empty(ctx, queue_url, wait_s=10.0), "denied publish unexpectedly delivered"

    # --- positive control: same handler, role WITH iot:Publish ---
    allowed_role_arn = _create_lambda_role(ctx, ["iot:Publish"])
    allowed_fn = _create_function(ctx, allowed_role_arn, _HANDLER_CODE)

    allowed_message = {"marker": ctx.unique_name("allowed-")}
    allowed_payload = _invoke_json(
        ctx, allowed_fn, {"endpoint_url": endpoint_url, "topic": topic, "message": allowed_message}
    )
    assert allowed_payload["success"] is True, (
        f"positive control publish (role WITH iot:Publish) unexpectedly failed: {allowed_payload!r}"
    )

    delivered = _poll_for_message(ctx, queue_url, timeout_s=60.0)
    assert delivered == allowed_message, (
        f"expected {allowed_message!r} delivered via the IoT rule, got {delivered!r}"
    )


def _make_zip(handler_code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", handler_code)
    return buf.getvalue()


def _create_lambda_role(ctx, iot_actions):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-iotlam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    logs_policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=logs_policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=logs_policy_arn))

    if iot_actions:
        policy_name = "iot-inline-access"
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": iot_actions, "Resource": "*"}],
        }
        iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    return role_arn


def _create_function(ctx, role_arn, handler_code):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-iotlam-fn-")
    zip_bytes = _make_zip(handler_code)
    last_err = None
    for _ in range(10):
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                MemorySize=128,
                Tags={"sim2real": CHECK},
            )
            break
        except lam.exceptions.InvalidParameterValueException as e:
            last_err = e
            time.sleep(3)
    else:
        raise AssertionError(f"function creation never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    waiter = lam.get_waiter("function_active_v2")
    waiter.wait(FunctionName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return name


def _invoke_json(ctx, name, payload=None):
    lam = ctx.client("lambda")
    resp = lam.invoke(FunctionName=name, Payload=json.dumps(payload or {}).encode("utf-8"))
    body = json.loads(resp["Payload"].read())
    if resp.get("FunctionError"):
        raise AssertionError(f"lambda invocation errored: {body}")
    return body


def _create_queue(ctx):
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-iotlam-q-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _create_topic_rule_to_sqs(ctx, topic, queue_url, queue_arn):
    iam = ctx.client("iam")
    iot = ctx.client("iot")

    role_name = ctx.unique_name("sim2real-iotlam-rulerole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "iot.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sqs-send"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    rule_name = ctx.unique_name("sim2real_iotlam_rule_")
    sql = f"SELECT * FROM '{topic}'"
    last_err = None
    for _ in range(10):
        try:
            iot.create_topic_rule(
                ruleName=rule_name,
                topicRulePayload={
                    "sql": sql,
                    "actions": [
                        {"sqs": {"roleArn": role_arn, "queueUrl": queue_url, "useBase64": False}}
                    ],
                    "ruleDisabled": False,
                },
                tags=f"sim2real={CHECK}",
            )
            break
        except iot.exceptions.InvalidRequestException as e:
            last_err = e
            time.sleep(3)
    else:
        raise AssertionError(f"topic rule creation never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_name))
    return rule_name


def _poll_for_message(ctx, queue_url, timeout_s=60.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
            return json.loads(msg["Body"])
    raise AssertionError(f"no message delivered to SQS within {timeout_s}s")


def _drained_empty(ctx, queue_url, wait_s=10.0):
    """Polls the queue for wait_s seconds; returns True iff no message ever arrived."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + wait_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2)
        if resp.get("Messages"):
            return False
    return True


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
