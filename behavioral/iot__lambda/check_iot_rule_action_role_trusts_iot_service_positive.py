"""iot-rule-action-role-trusts-iot-service-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "iot-rule-action-role-trusts-iot-service-positive"
GROUP = "iam-trust"
SERVICES = ["iot", "lambda"]

_BASIC_EXEC_POLICY = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
_TAGS = {"sim2real:managed": "true"}


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Lambda resource policy granting iot.amazonaws.com lambda:InvokeFunction for a topic rule's exact ARN lets
    the rule's lambda action invoke the function, which forwards the published marker to SQS."""
    queue_url, queue_arn = _create_sqs_queue(ctx)
    role_arn, _role_name = _create_role(
        ctx,
        ["lambda.amazonaws.com"],
        inline_policies={
            "forward-to-sqs": {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}
                ],
            }
        },
        managed_policy_arns=[_BASIC_EXEC_POLICY],
    )
    fn_name = ctx.unique_name("sim2real-iotlambda-fn-")
    _create_function_with_retry(
        ctx, fn_name, role_arn, _lambda_zip_forward_to_sqs(), env={"QUEUE_URL": queue_url}
    )
    lam = ctx.client("lambda")
    fn_arn = lam.get_function_configuration(FunctionName=fn_name)["FunctionArn"]

    topic = ctx.unique_name("sim2real-iotlambda-topic-")
    rule_name = _create_topic_rule(ctx, fn_arn, topic)
    rule_arn, account_id = _rule_arn(ctx, rule_name)
    _grant_iot_invoke(ctx, fn_name, rule_arn, account_id)

    marker = ctx.unique_name("marker-")
    iot_data = _iot_data_client(ctx)
    msg = _publish_until_delivered(
        ctx, iot_data, topic, {"marker": marker}, queue_url, timeout_s=90.0
    )
    assert msg is not None, "expected the IoT rule's lambda action to deliver a message via SQS"
    assert msg.get("marker") == marker, f"expected marker {marker!r}, got {msg!r}"


def _lambda_zip_forward_to_sqs() -> bytes:
    src = (
        "import json, os, boto3\n"
        "def handler(event, context):\n"
        "    sqs = boto3.client('sqs')\n"
        "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], MessageBody=json.dumps(event))\n"
        "    return {'forwarded': True}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("lambda_function.py", src)
    return buf.getvalue()


def _create_role(ctx, principals, inline_policies=None, managed_policy_arns=None):
    iam = ctx.client("iam")
    principal = principals[0] if len(principals) == 1 else principals
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": principal}, "Action": "sts:AssumeRole"}
        ],
    }
    name = ctx.unique_name("sim2real-iotlambda-role-")
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    for policy_name, doc in (inline_policies or {}).items():
        iam.put_role_policy(RoleName=name, PolicyName=policy_name, PolicyDocument=json.dumps(doc))
    for arn in managed_policy_arns or []:
        iam.attach_role_policy(RoleName=name, PolicyArn=arn)
    role = iam.get_role(RoleName=name)["Role"]
    return role["Arn"], name


def _delete_role(ctx, role_name) -> None:
    iam = ctx.client("iam")
    try:
        for p in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=p)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for p in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=p["PolicyArn"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_function_with_retry(ctx, name, role_arn, zip_bytes, env=None, timeout_s=90.0):
    lam = ctx.client("lambda")
    kwargs = dict(
        FunctionName=name,
        Runtime="python3.12",
        Role=role_arn,
        Handler="lambda_function.handler",
        Code={"ZipFile": zip_bytes},
        Timeout=30,
        Tags=_TAGS,
    )
    if env is not None:
        kwargs["Environment"] = {"Variables": env}
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(**kwargs)
            ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
            return resp
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            last_err = e
            if code == "InvalidParameterValueException" and "cannot be assumed" in msg:
                time.sleep(3)
                continue
            raise
    raise last_err


def _create_sqs_queue(ctx):
    sqs = ctx.client("sqs")
    url = sqs.create_queue(
        QueueName=ctx.unique_name("sim2real-iotlambda-q-"), tags=_TAGS
    )["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _create_topic_rule(ctx, function_arn, topic):
    iot = ctx.client("iot")
    rule_name = ctx.unique_name("sim2real_iotlambda_rule_").replace("-", "_")
    iot.create_topic_rule(
        ruleName=rule_name,
        topicRulePayload={
            "sql": f"SELECT * FROM '{topic}'",
            "awsIotSqlVersion": "2016-03-23",
            "actions": [{"lambda": {"functionArn": function_arn}}],
            "ruleDisabled": False,
        },
    )
    ctx.on_cleanup(lambda: iot.delete_topic_rule(ruleName=rule_name))
    return rule_name


def _rule_arn(ctx, rule_name):
    sts = ctx.client("sts")
    ident = sts.get_caller_identity()
    partition = ident["Arn"].split(":")[1]
    return f"arn:{partition}:iot:{ctx.region}:{ident['Account']}:rule/{rule_name}", ident[
        "Account"
    ]


def _grant_iot_invoke(ctx, function_name, source_arn, source_account, statement_id=None):
    lam = ctx.client("lambda")
    sid = statement_id or ctx.unique_name("sim2real-iotlambda-perm-")
    lam.add_permission(
        FunctionName=function_name,
        StatementId=sid,
        Action="lambda:InvokeFunction",
        Principal="iot.amazonaws.com",
        SourceArn=source_arn,
        SourceAccount=source_account,
    )


def _iot_data_client(ctx):
    iot = ctx.client("iot")
    endpoint = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    client = ctx.client("iot-data", endpoint_url=ctx.endpoint_url(endpoint))
    _wait_for_iot_data_ready(client)
    return client


def _wait_for_iot_data_ready(iot_data, timeout_s=180.0, interval_s=5.0):
    """The per-account IoT data-ATS endpoint can take a short time to become reachable
    (DNS/cert propagation) right after being (re)provisioned; retry a harmless publish
    until it stops raising a connection error."""
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


def _publish_until_delivered(
    ctx, iot_data, topic, payload, queue_url, timeout_s=90.0, republish_interval_s=8.0
):
    """Newly created IoT topic rules take a few seconds to become effective in the rules
    engine, so a single publish sent right after CreateTopicRule can be missed. Republish
    periodically while polling SQS until the message shows up or the deadline passes."""
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    next_publish = 0.0
    while time.monotonic() < deadline:
        if time.monotonic() >= next_publish:
            try:
                iot_data.publish(topic=topic, qos=0, payload=json.dumps(payload))
            except Exception:  # noqa: BLE001 - transient connectivity, keep polling/retrying
                pass
            next_publish = time.monotonic() + republish_interval_s
        remaining = max(1, min(5, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=remaining
        )
        msgs = resp.get("Messages", [])
        if msgs:
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
            try:
                return json.loads(msgs[0]["Body"])
            except ValueError:
                return msgs[0]["Body"]
    return None


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
