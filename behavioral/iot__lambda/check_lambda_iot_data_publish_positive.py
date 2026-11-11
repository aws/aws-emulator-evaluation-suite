"""lambda-iot-data-publish-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "lambda-iot-data-publish-positive"
GROUP = "data-plane-sdk"
SERVICES = ["iot", "lambda"]

_HANDLER_CODE = """
import boto3
import json

def lambda_handler(event, context):
    client = boto3.client("iot-data", endpoint_url=event["endpoint_url"])
    client.publish(
        topic=event["topic"],
        qos=0,
        payload=json.dumps(event["message"]).encode("utf-8"),
    )
    return {"success": True}
"""


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda whose role grants iot:Publish publishes via iot-data without a FunctionError,
    and an IoT topic rule forwarding to SQS proves the exact payload reached the broker."""
    iot = ctx.client("iot")
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    endpoint_url = ctx.endpoint_url(endpoint)

    topic = ctx.unique_name("sim2real/iotlam/pub/")
    queue_url, queue_arn = _create_queue(ctx)
    _create_topic_rule_to_sqs(ctx, topic, queue_url, queue_arn)

    role_arn = _create_lambda_role(ctx, ["iot:Publish"])
    fn_name = _create_function(ctx, role_arn, _HANDLER_CODE)

    message = {"marker": ctx.unique_name("pub-"), "value": 42}
    payload = _invoke_json(
        ctx, fn_name, {"endpoint_url": endpoint_url, "topic": topic, "message": message}
    )
    assert payload["success"] is True, f"expected success=True from the handler, got {payload!r}"

    delivered = _poll_for_message(ctx, queue_url, timeout_s=60.0)
    assert delivered == message, f"expected the published message {message!r} to arrive via the topic rule, got {delivered!r}"


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
        Tags=[{"Key": "sim2real", "Value": "check_lambda_iot_data_publish_positive"}],
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
                Tags={"sim2real": "check_lambda_iot_data_publish_positive"},
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
    url = sqs.create_queue(
        QueueName=name, tags={"sim2real": "check_lambda_iot_data_publish_positive"}
    )["QueueUrl"]
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
        Tags=[{"Key": "sim2real", "Value": "check_lambda_iot_data_publish_positive"}],
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
            )
            break
        except iot.exceptions.InvalidRequestException as e:
            last_err = e
            time.sleep(3)
    else:
        raise AssertionError(f"topic rule creation never succeeded (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_name))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    rule_arn = f"arn:aws:iot:{ctx.region}:{account_id}:rule/{rule_name}"
    iot.tag_resource(
        resourceArn=rule_arn,
        tags=[{"Key": "sim2real", "Value": "check_lambda_iot_data_publish_positive"}],
    )
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
